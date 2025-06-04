package net.pincette.mongo.claims;

import static com.auth0.jwt.JWT.decode;
import static com.mongodb.reactivestreams.client.MongoClients.create;
import static com.typesafe.config.ConfigFactory.defaultApplication;
import static com.typesafe.config.ConfigFactory.defaultOverrides;
import static java.time.Duration.ofSeconds;
import static java.time.Instant.now;
import static java.util.Objects.requireNonNull;
import static java.util.Optional.ofNullable;
import static java.util.concurrent.CompletableFuture.completedFuture;
import static java.util.logging.Level.FINEST;
import static java.util.logging.Logger.getLogger;
import static net.pincette.json.JsonUtil.createReader;
import static net.pincette.json.JsonUtil.createValue;
import static net.pincette.json.JsonUtil.isString;
import static net.pincette.json.JsonUtil.merge;
import static net.pincette.json.JsonUtil.string;
import static net.pincette.json.JsonUtil.stringValue;
import static net.pincette.json.Transform.transform;
import static net.pincette.jwt.Util.getJwtPayload;
import static net.pincette.mongo.JsonClient.aggregate;
import static net.pincette.util.Collections.concat;
import static net.pincette.util.Collections.flatten;
import static net.pincette.util.Collections.list;
import static net.pincette.util.Collections.map;
import static net.pincette.util.Or.tryWith;
import static net.pincette.util.Pair.pair;
import static net.pincette.util.Util.replaceParameters;
import static net.pincette.util.Util.tryToGet;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.mongodb.reactivestreams.client.MongoCollection;
import com.typesafe.config.Config;
import java.io.File;
import java.io.StringReader;
import java.net.http.HttpHeaders;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletionStage;
import java.util.function.Supplier;
import java.util.logging.Logger;
import java.util.stream.Stream;
import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.json.JsonValue;
import net.pincette.http.headers.plugin.Plugin;
import net.pincette.http.headers.plugin.RequestResult;
import net.pincette.http.headers.plugin.Response;
import net.pincette.json.JsonUtil;
import net.pincette.json.Transform.JsonEntry;
import net.pincette.json.Transform.Transformer;
import net.pincette.jwt.Signer;
import net.pincette.jwt.Verifier;
import org.bson.Document;

/**
 * A plugin for <code>net.pincette.http.headers</code> that adds claims to a given bearer token. All
 * the fields in the object that is found through the MongoDB query are added as claims. The query
 * should always return exactly one object, otherwise nothing is added.
 *
 * @author Werner Donné
 */
public class ClaimsPlugin implements Plugin {
  private static final String AGGREGATION_PIPELINE = "aggregationPipeline";
  private static final String AUTHORIZATION = "Authorization";
  private static final String BEARER = "Bearer";
  private static final String COLLECTION = "collection";
  private static final String COOKIE = "Cookie";
  private static final String DATABASE = "database";
  private static final String HOST = "Host";
  private static final Logger LOGGER = getLogger("net.pincette.mongo.claims");
  private static final String MONGO_CLAIMS = "mongoClaims";
  private static final String MONGO_CLAIMS_COOKIE = "mongo_claims";
  private static final String PRIVATE_KEY = "privateKey";
  private static final String PUBLIC_KEY = "publicKey";
  private static final String SET_COOKIE = "Set-Cookie";
  private static final String URI = "uri";

  private JsonArray aggregationPipeline;
  private Config config;
  private long loaded = -1;
  private MongoCollection<Document> mongoCollection;
  private Signer signer;
  private Verifier verifier;

  private static HttpHeaders addHeader(
      final HttpHeaders headers, final String name, final String value) {
    return setHeader(headers, name, list(value), false);
  }

  private static Optional<File> configFile(final Config config) {
    return ofNullable(config.origin().filename()).map(File::new);
  }

  private static Map<String, String> cookies(final HttpHeaders headers) {
    return map(
        ofNullable(headers.allValues(COOKIE)).stream()
            .flatMap(List::stream)
            .flatMap(v -> Stream.of(v.split("; ")))
            .map(v -> v.split("="))
            .filter(s -> s.length == 2)
            .map(s -> pair(s[0], s[1])));
  }

  private static String domain(final HttpHeaders headers) {
    return headers.firstValue(HOST).map(h -> h.split(":")[0]).orElse("");
  }

  private static Map<String, String> flattenToken(final JsonObject token) {
    return map(
        flatten(token, ".").entrySet().stream()
            .map(
                e ->
                    pair(
                        e.getKey(),
                        stringValue(createValue(e.getValue()))
                            .orElseGet(() -> e.getValue().toString()))));
  }

  private static RequestResult forwardWithToken(
      final HttpHeaders headers, final String token, final boolean cookie) {
    final RequestResult result = new RequestResult().withRequest(setBearerToken(headers, token));

    return cookie
        ? result.withResponseWrapper(
            h ->
                completedFuture(setCookie(h, token, domain(headers)))
                    .thenApply(withCookie -> trace(withCookie, () -> "set cookie: " + withCookie)))
        : result;
  }

  private static Optional<String> getBearerToken(final HttpHeaders headers) {
    return headers
        .firstValue(AUTHORIZATION)
        .map(header -> header.split(" "))
        .filter(s -> s.length == 2)
        .filter(s -> s[0].equalsIgnoreCase(BEARER))
        .map(s -> s[1]);
  }

  private static boolean matchesIdToken(
      final DecodedJWT mongoClaimsToken, final HttpHeaders headers) {
    return getBearerToken(headers)
        .map(JWT::decode)
        .map(idToken -> matchesIdToken(mongoClaimsToken, idToken))
        .orElse(false);
  }

  private static boolean matchesIdToken(
      final DecodedJWT mongoClaimsToken, final DecodedJWT idToken) {
    return mongoClaimsToken.getIssuer().equals(idToken.getIssuer())
        && idToken.getIssuedAtAsInstant().isBefore(mongoClaimsToken.getIssuedAtAsInstant());
  }

  private static JsonArray resolveAggregationPipeline(
      final JsonArray aggregationPipeline, final JsonObject idTokenPayload) {
    final Map<String, String> flattened = flattenToken(idTokenPayload);

    final JsonArray result =
        transform(
            aggregationPipeline,
            new Transformer(
                e -> isString(e.value),
                e -> Optional.of(new JsonEntry(e.path, resolveScalar(e.value, flattened)))));

    return trace(result, () -> string(result, false));
  }

  private static JsonValue resolveScalar(
      final JsonValue value, final Map<String, String> flattened) {
    return stringValue(value).map(s -> createValue(replaceParameters(s, flattened))).orElse(value);
  }

  private static HttpHeaders setBearerToken(final HttpHeaders headers, final String token) {
    return setHeader(headers, AUTHORIZATION, BEARER + " " + token);
  }

  private static HttpHeaders setCookie(
      final HttpHeaders headers, final String token, final String domain) {
    return addHeader(
        headers,
        SET_COOKIE,
        MONGO_CLAIMS_COOKIE
            + "="
            + token
            + "; HttpOnly ; Path=/; SameSite=None; Secure; Domain="
            + domain);
  }

  private static HttpHeaders setHeader(
      final HttpHeaders headers, final String name, final String value) {
    return setHeader(headers, name, list(value), true);
  }

  private static HttpHeaders setHeader(
      final HttpHeaders headers,
      final String name,
      final List<String> value,
      final boolean replace) {
    return HttpHeaders.of(
        net.pincette.util.Collections.merge(
            Stream.of(headers.map(), map(pair(name, value))),
            String::toLowerCase,
            (v1, v2) -> replace ? v2 : concat(v1, v2)),
        (k, v) -> true);
  }

  private static <T> T trace(final T v, final Supplier<String> message) {
    LOGGER.log(FINEST, message);

    return v;
  }

  private Optional<CompletionStage<String>> createToken(final HttpHeaders headers) {
    return getBearerToken(headers)
        .flatMap(
            token ->
                getJwtPayload(token)
                    .map(
                        payload ->
                            findClaims(
                                    resolveAggregationPipeline(getAggregationPipeline(), payload))
                                .thenApply(claims -> merge(payload, claims))
                                .thenApply(merged -> createToken(token, merged))));
  }

  private String createToken(final String idToken, final JsonObject payload) {
    final DecodedJWT decoded = decode(idToken);

    return getSigner()
        .sign(
            JWT.create()
                .withPayload(string(payload))
                .withAudience(decoded.getAudience().toArray(String[]::new))
                .withIssuer(decoded.getIssuer())
                .withExpiresAt(decoded.getExpiresAtAsInstant().plus(ofSeconds(5)))
                .withIssuedAt(now()));
  }

  private CompletionStage<JsonObject> findClaims(final JsonArray aggregationPipeline) {
    return aggregate(getCollection(), aggregationPipeline)
        .thenApply(
            result ->
                Optional.of(result)
                    .filter(r -> r.size() == 1)
                    .map(r -> r.get(0))
                    .orElseGet(JsonUtil::emptyObject));
  }

  private JsonArray getAggregationPipeline() {
    reloadIfChanged();

    return aggregationPipeline;
  }

  private MongoCollection<Document> getCollection() {
    reloadIfChanged();

    return mongoCollection;
  }

  private Signer getSigner() {
    reloadIfChanged();

    return signer;
  }

  private Optional<String> getToken(final HttpHeaders headers) {
    final String token = cookies(headers).get(MONGO_CLAIMS_COOKIE);

    return ofNullable(token)
        .flatMap(getVerifier()::verify)
        .filter(t -> matchesIdToken(t, headers))
        .map(t -> token);
  }

  private Verifier getVerifier() {
    reloadIfChanged();

    return verifier;
  }

  private boolean hasChanged(final Config config) {
    return configFile(config)
        .map(File::lastModified)
        .map(modified -> modified > loaded)
        .orElse(false);
  }

  private void loadAggregationPipeline() {
    aggregationPipeline =
        requireNonNull(
            tryToGet(
                    () ->
                        createReader(new StringReader(config.getString(AGGREGATION_PIPELINE)))
                            .read(),
                    e -> {
                      LOGGER.severe(e::getMessage);
                      return null;
                    })
                .flatMap(JsonUtil::arrayValue)
                .orElse(null));
  }

  @SuppressWarnings("java:S2095") // The collection needs the client to stay alive.
  private void loadCollection() {
    mongoCollection =
        create(config.getString(URI))
            .getDatabase(config.getString(DATABASE))
            .getCollection(config.getString(COLLECTION));
  }

  private void loadConfig() {
    config = defaultOverrides().withFallback(defaultApplication()).getConfig(MONGO_CLAIMS);
    loaded = now().toEpochMilli();
  }

  private boolean missing() {
    return mongoCollection == null
        || aggregationPipeline == null
        || signer == null
        || verifier == null;
  }

  private void reloadIfChanged() {
    if (config == null || hasChanged(config) || missing()) {
      loadConfig();
      loadCollection();
      loadAggregationPipeline();
      signer = new Signer(config.getString(PRIVATE_KEY));
      verifier = new Verifier(config.getString(PUBLIC_KEY));
    }
  }

  public CompletionStage<RequestResult> request(final HttpHeaders headers) {
    return tryWith(
            () ->
                getToken(trace(headers, () -> "request headers " + headers))
                    .map(
                        t ->
                            (CompletionStage<RequestResult>)
                                completedFuture(forwardWithToken(headers, t, false))))
        .or(
            () ->
                createToken(headers)
                    .map(token -> token.thenApply(t -> forwardWithToken(headers, t, true))))
        .get()
        .orElseGet(
            () ->
                completedFuture(
                    new RequestResult().withResponse(new Response().withStatusCode(401))))
        .thenApply(result -> trace(result, () -> "request result: " + result));
  }

  public CompletionStage<HttpHeaders> response(final HttpHeaders headers) {
    return completedFuture(headers);
  }
}

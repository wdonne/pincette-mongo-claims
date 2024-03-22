import net.pincette.mongo.claims.ClaimsPlugin;

module net.pincette.mongo.claims {
  requires net.pincette.http.headers.plugin;
  requires java.net.http;
  requires net.pincette.common;
  requires net.pincette.jwt;
  requires typesafe.config;
  requires org.mongodb.bson;
  requires org.mongodb.driver.reactivestreams;
  requires java.json;
  requires net.pincette.json;
  requires net.pincette.mongo;
  requires com.auth0.jwt;
  requires java.logging;

  provides net.pincette.http.headers.plugin.Plugin with
      ClaimsPlugin;
}

# Mongo Claims

This is a plugin for [HTTP Headers](https://github.com/wdonne/pincette-http-headers). It expects to find a validated JSON Web Token as a bearer token. It extends and resigns the token with the output of a MongoDB aggregation pipeline. This output constitutes additional claims for the user. The resulting JWT is set as a bearer token on the forwarded request. 

## Configuration

The configuration is managed by the [Lightbend Config package](https://github.com/lightbend/config). By default it will try to load `conf/application.conf`. An alternative configuration may be loaded by adding `-Dconfig.resource=myconfig.conf`, where the file is also supposed to be in the `conf` directory, or `-Dconfig.file=/conf/myconfig.conf`. If no configuration file is available it will load a default one from the resources. The following entries are available:

|Entry|Mandatory|Description|
|---|---|---|
|mongoClaims.aggregationPipeline|Yes|The MongpoDB aggregation pipeline. All the fields it returns will be added as claims. The result set should have only one entry. Fields in the incoming JWT can be addressed in a pipeline as `${<dot.separated.path>}`. If the value doesn't exist in the token, the result is an empty string.|
|mongoClaims.database|Yes|The MongoDB database.|
|mongoClaims.collection|Yes|The MongoDB collection that will be queried.|
|mongoClaims.issuer|No|The `issuer` field in the generated JWT. It will be the empty string if not set.|
|mongoClaims.privateKey|Yes|The private key in PEM format that will be used to sign the generates JWTs.|
|mongoClaims.publicKey|Yes|The public key in PEM format that will be used to verify its own JWTs.|
|mongoClaims.uri|Yes|The MongoDB URI.|

## Docker

Docker images can be found at [https://hub.docker.com/repository/docker/wdonne/pincette-mongo-claims](https://hub.docker.com/repository/docker/wdonne/pincette-mongo-claims). Its entry point copies the plugin to the `/plugins` folder.

## Kubernetes

You can mount the configuration in a `ConfigMap` and `Secret` combination. The `ConfigMap` should be mounted at `/conf/application.conf`. You then include the secret in the configuration from where you have mounted it. See also [https://github.com/lightbend/config/blob/main/HOCON.md#include-syntax](https://github.com/lightbend/config/blob/main/HOCON.md#include-syntax).

The above-mentioned container image can be used for an init container. It assumes the existence of a writable folder called `/plugins`, which can be the mount of an `emptyDir`.

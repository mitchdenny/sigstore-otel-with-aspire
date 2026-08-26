FROM maven:3.9.11-eclipse-temurin-21 AS build

WORKDIR /src

COPY pom.xml ./
COPY src ./src

RUN --mount=type=cache,target=/root/.m2 \
    mvn --batch-mode --quiet --no-transfer-progress package \
      dependency:copy-dependencies \
      -DincludeScope=runtime \
      -DoutputDirectory=/out/lib \
    && mvn --batch-mode --quiet --no-transfer-progress dependency:copy \
      -Dartifact=io.opentelemetry.javaagent:opentelemetry-javaagent:2.31.1 \
      -DoutputDirectory=/out/otel \
      -Dmdep.stripVersion=true

FROM eclipse-temurin:21-jre-jammy

ARG SIGSTORE_JAVA_FIXTURE_COMMIT=55eec241079bb51605eef2dd79f8f28e1e915e3c
ARG SIGSTORE_JAVA_FIXTURE_BASE=https://raw.githubusercontent.com/sigstore/sigstore-java

RUN useradd --create-home --uid 10001 probe

COPY --from=build /src/target/sigstore-java-telemetry-probe-1.0.0.jar /app/probe.jar
COPY --from=build /out/lib /app/lib
COPY --from=build /out/otel/opentelemetry-javaagent.jar /otel/opentelemetry-javaagent.jar

ADD --checksum=sha256:a0cfc71271d6e278e57cd332ff957c3f7043fdda354c4cbb190a30d56efa01bf \
    ${SIGSTORE_JAVA_FIXTURE_BASE}/${SIGSTORE_JAVA_FIXTURE_COMMIT}/sigstore-java/src/test/resources/dev/sigstore/samples/bundles/artifact.txt \
    /opt/sigstore-java-fixture/artifact.txt
ADD --checksum=sha256:04da78642a58f894c26e0c0ab6a3b8f2438e64d865bbc1efd7889dd14a7592e4 \
    ${SIGSTORE_JAVA_FIXTURE_BASE}/${SIGSTORE_JAVA_FIXTURE_COMMIT}/sigstore-java/src/test/resources/dev/sigstore/samples/bundles/bundle.sigstore \
    /opt/sigstore-java-fixture/bundle.sigstore.json

RUN chmod 0444 \
    /opt/sigstore-java-fixture/artifact.txt \
    /opt/sigstore-java-fixture/bundle.sigstore.json

USER probe

ENTRYPOINT ["java", "-javaagent:/otel/opentelemetry-javaagent.jar", "-cp", "/app/probe.jar:/app/lib/*", "example.TelemetryProbe"]

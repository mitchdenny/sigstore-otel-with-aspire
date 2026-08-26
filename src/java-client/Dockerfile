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

RUN useradd --create-home --uid 10001 probe

COPY --from=build /src/target/sigstore-java-client-1.0.0.jar /app/client.jar
COPY --from=build /out/lib /app/lib
COPY --from=build /out/otel/opentelemetry-javaagent.jar /otel/opentelemetry-javaagent.jar

USER probe

EXPOSE 8080
ENTRYPOINT ["java", "-javaagent:/otel/opentelemetry-javaagent.jar", "-cp", "/app/client.jar:/app/lib/*", "example.SigstoreClient"]

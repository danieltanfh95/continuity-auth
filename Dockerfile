# --- build stage ---
FROM clojure:temurin-21-tools-deps-bookworm AS build
WORKDIR /build
COPY deps.edn .
RUN clojure -P
COPY src ./src
COPY resources ./resources
COPY build.clj .
RUN clojure -T:build uber

# Generate AppCDS archive — speeds JVM startup.
RUN java -XX:ArchiveClassesAtExit=/build/app.jsa \
         -jar /build/target/continuity-auth.jar --selftest || true

# --- runtime stage ---
FROM eclipse-temurin:21-jre-alpine AS runtime
RUN addgroup -S cauth && adduser -S cauth -G cauth
WORKDIR /app
COPY --from=build /build/target/continuity-auth.jar /app/continuity-auth.jar
COPY --from=build /build/app.jsa /app/app.jsa
COPY resources/logback.xml /app/logback.xml

ENV JAVA_OPTS="-XX:+UseG1GC -XX:MaxRAMPercentage=75 -XX:SharedArchiveFile=/app/app.jsa -Dlogback.configurationFile=/app/logback.xml -Dfile.encoding=UTF-8"
ENV CONTINUITY_AUTH_HTTP_HOST=0.0.0.0
ENV CONTINUITY_AUTH_HTTP_PORT=8080

USER cauth
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=2s --start-period=15s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8080/healthz || exit 1

ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar /app/continuity-auth.jar"]

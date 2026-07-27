FROM maven:3.9-eclipse-temurin-21-alpine AS build
WORKDIR /app
COPY pom.xml .
RUN mvn dependency:go-offline -B --no-transfer-progress || true
COPY . .
RUN mvn package -DskipTests -B --no-transfer-progress

FROM eclipse-temurin:21-jre-alpine
WORKDIR /app
RUN apk add --no-cache curl softhsm
COPY --from=build /app/target/*.jar app.jar

# Create non-root user for security
RUN addgroup -S pkigroup && adduser -S pkiuser -G pkigroup

# Configure SoftHSM
RUN mkdir -p /var/lib/softhsm/tokens && chown -R pkiuser:pkigroup /var/lib/softhsm

COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

USER pkiuser

EXPOSE 8080
ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["java", "-jar", "app.jar"]

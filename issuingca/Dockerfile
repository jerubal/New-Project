FROM eclipse-temurin:21-jdk-alpine AS build
WORKDIR /app
COPY . .
RUN ./mvnw package -DskipTests --no-transfer-progress

FROM eclipse-temurin:21-jre-alpine
WORKDIR /app
COPY --from=build /app/target/*.jar app.jar

# Create non-root user for security
RUN addgroup -S pkigroup && adduser -S pkiuser -G pkigroup
USER pkiuser

EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]

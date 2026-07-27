FROM maven:3.9-eclipse-temurin-21-alpine AS build
WORKDIR /app
COPY pom.xml .
RUN mvn dependency:go-offline -B --no-transfer-progress || true
COPY . .
RUN mvn package -DskipTests -B --no-transfer-progress

FROM eclipse-temurin:21-jre-alpine
WORKDIR /app
RUN apk add --no-cache curl
COPY --from=build /app/target/*.jar app.jar

# Create non-root user for security
RUN addgroup -S pkigroup && adduser -S pkiuser -G pkigroup
USER pkiuser

EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]

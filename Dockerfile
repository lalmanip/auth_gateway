FROM maven:3.9.9-eclipse-temurin-17 AS builder

WORKDIR /build

# Copy only pom first (better cache usage)
COPY pom.xml .

# Download dependencies (cached)
RUN --mount=type=cache,target=/root/.m2 \
    mvn -B dependency:go-offline

# Copy source
COPY src ./src

# Build application
RUN --mount=type=cache,target=/root/.m2 \
    mvn -B clean package -DskipTests

# ===============================
# Runtime image
# ===============================
FROM eclipse-temurin:17-jdk

WORKDIR /app

COPY --from=builder /build/target/*.jar app.jar

EXPOSE 8084

ENTRYPOINT ["java", "-jar", "app.jar"]

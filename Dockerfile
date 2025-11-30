# Build stage
FROM gradle:8-jdk21 AS build
WORKDIR /app

# Copy Gradle files
COPY gradle/ ./gradle/
COPY gradlew ./
COPY gradlew.bat ./
COPY build.gradle.kts ./
COPY settings.gradle.kts ./
COPY gradle.properties ./

# Copy source code
COPY app/ ./app/
COPY model/ ./model/
COPY shared/ ./shared/
COPY ui/ ./ui/

# Build the ShadowJar
RUN ./gradlew app:shadowJar --no-daemon

# Runtime stage
FROM eclipse-temurin:21-jre-ubi9-minimal
WORKDIR /app

# Copy the built JAR from the build stage
COPY --from=build /app/app/build/libs/*-all.jar app.jar

# Copy bootstrap files
COPY app/docker/bootstrap/ /bootstrap/

# Set environment variables
ENV JAVA_TOOL_OPTIONS="-Xms64M -Xmx192M"
ENV MICRONAUT_CONFIG_FILES="/config/kuvasz.yml"

# Expose port
EXPOSE 8080

# Run the application
ENTRYPOINT ["java", "-jar", "app.jar"]


# Stage 1: Build the application
FROM maven:3.9.9-ibm-semeru-23-jammy AS build
WORKDIR /app

COPY mvnw ./
COPY .mvn .mvn
COPY pom.xml ./
COPY src/ ./src

RUN chmod +x mvnw && \
    ./mvnw install -DskipTests
# Package the application (this creates the JAR file)
RUN mvn clean package -DskipTests

# Stage 2: Run the application
FROM openjdk:23-jdk-slim
WORKDIR /app

# Copy the built JAR from the first stage
COPY --from=build /app/target/summonerssync.apigateway-0.0.1-SNAPSHOT.jar app.jar

# Expose the port the app runs on
EXPOSE 8080

# Run Spring Boot app
CMD ["java", "-jar", "app.jar"]
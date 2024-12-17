# Stage 1: Build the application
FROM maven:3.9.6-eclipse-temurin-23 AS build
WORKDIR /app

# Copy the Maven project files
COPY pom.xml .
COPY src ./src

# Package the application (this creates the JAR file)
RUN mvn clean package -DskipTests

# Stage 2: Run the application
FROM openjdk:23-jdk-slim
WORKDIR /app

# Copy the built JAR from the first stage
COPY --from=build /app/target/api-gateway-0.0.1-SNAPSHOT.jar app.jar

# Expose the port the app runs on
EXPOSE 8080

# Run Spring Boot app
CMD ["sh", "-c", "ls -lh && java -jar app.jar"]
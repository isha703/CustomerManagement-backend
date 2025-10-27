# CustManagement Backend

Spring Boot backend for customer management with OAuth2 Resource Server (Google) support, PostgreSQL, Flyway, and production-ready configs.

Requirements:
- Java 17
- Maven
- Docker (optional)

Environment variables (examples):

- DB_HOST, DB_PORT, DB_NAME, DB_USERNAME, DB_PASSWORD
- SPRING_PROFILES_ACTIVE=prod
- APP_CORS_ALLOWED_ORIGINS

Run locally:

1. Start Postgres (local or via docker-compose):
   docker-compose up -d

2. Build:
   mvn -DskipTests package

3. Run:
   java -jar target/custmanagement-0.0.1-SNAPSHOT.jar

Running in Docker:
1. Build image:
   docker build -t custmanagement:latest .

2. Start postgres and app using docker-compose (customize to add the app service):
   docker-compose up -d

Security:
- The application is configured as an OAuth2 Resource Server validating JWTs (e.g., from Google). Configure `spring.security.oauth2.resourceserver.jwt.issuer-uri` in your environment or profiles.

Notes:
- CORS is configured to allow http://localhost:8081 by default.
- Use secure environment variables in production and set `spring.profiles.active=prod`.


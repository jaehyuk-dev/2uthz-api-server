# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Spring Boot API server project using Java 21 and Gradle. The project structure follows standard Spring Boot conventions with a corrected package name (`com._uthz.api_server` instead of the invalid `com.2uthz.api-server`).

## Essential Commands

### Build and Run
- `./gradlew build` - Build the project
- `./gradlew bootRun` - Run the Spring Boot application
- `./gradlew clean` - Clean build artifacts

### Testing
- `./gradlew test` - Run all tests
- `./gradlew test --tests ClassName` - Run specific test class
- `./gradlew test --tests ClassName.methodName` - Run specific test method

### Development
- `./gradlew bootRun --args='--spring.profiles.active=dev'` - Run with dev profile
- `./gradlew classes` - Compile without running tests

## Architecture

### Technology Stack
- **Framework**: Spring Boot 3.5.0
- **Java Version**: 21
- **Database**: H2 (in-memory for development/testing)
- **ORM**: Spring Data JPA
- **Build Tool**: Gradle with Gradle Wrapper

### Project Structure
- Main application class: `src/main/java/com/_uthz/api_server/ApiServerApplication.java`
- Package structure uses `com._uthz.api_server` (note the underscore prefix to handle the numeric start)
- Standard Spring Boot layout with `src/main/java`, `src/main/resources`, and `src/test/java`

### Key Dependencies
- `spring-boot-starter-web` - REST API capabilities
- `spring-boot-starter-data-jpa` - Database access layer
- `lombok` - Code generation for boilerplate reduction
- `h2` - Embedded database for development
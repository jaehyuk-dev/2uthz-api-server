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

## Coding Guidelines

### Comment Requirements (MANDATORY)
All code written in this project must include comprehensive and intuitive comments following these rules:

1. **Class Documentation**
    - Explain the class purpose and main responsibilities
    - Include key functionality overview
    - Add usage notes or important considerations

2. **Method Documentation**
    - Document method purpose and functionality
    - Explain parameters and their constraints
    - Describe return values and possible outcomes
    - Note any exceptions that may be thrown

3. **Inline Comments**
    - Explain complex business logic and algorithms
    - Clarify non-obvious code sections
    - Document the reasoning behind implementation decisions
    - Add step-by-step explanations for complex processes

4. **Variable Comments**
    - Explain unclear variable purposes
    - Document important constants and configuration values
    - Clarify magic numbers with meaningful explanations

### Documentation Standards
- Use clear, descriptive language
- Focus on explaining "why" rather than just "what"
- Write comments that help future developers understand the code quickly
- Include Javadoc for all public methods and classes
- Add TODO comments with specific action items when needed

**Important**: Never write code without proper comments. All code should be self-documenting through comprehensive comments that make the logic and purpose immediately clear to any developer reading it.
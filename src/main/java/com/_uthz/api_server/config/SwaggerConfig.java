package com._uthz.api_server.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

/**
 * Configuration class for Swagger/OpenAPI 3 documentation.
 * 
 * This configuration sets up comprehensive API documentation with Swagger UI,
 * including JWT Bearer token authentication support for testing API endpoints
 * directly from the documentation interface.
 * 
 * Key features:
 * - OpenAPI 3 specification with detailed API information
 * - JWT Bearer token security scheme configuration
 * - Interactive Swagger UI for API testing
 * - Comprehensive API metadata (title, description, version, contact)
 * - Server configuration for different environments
 * - Security requirements for protected endpoints
 * 
 * Swagger UI Access:
 * - Development: http://localhost:8080/swagger-ui.html
 * - API Docs JSON: http://localhost:8080/v3/api-docs
 * 
 * Security Configuration:
 * - Bearer token authentication scheme
 * - Authorization header format: "Bearer {token}"
 * - JWT token testing support in Swagger UI
 * 
 * Usage Instructions:
 * 1. Access Swagger UI at /swagger-ui.html
 * 2. Authenticate using login endpoint to get JWT token
 * 3. Click "Authorize" button in Swagger UI
 * 4. Enter "Bearer {your-jwt-token}" in the authorization field
 * 5. Test protected endpoints with automatic token inclusion
 */
@Configuration
public class SwaggerConfig {

    /**
     * Application version for API documentation.
     * Retrieved from application properties or defaults to development version.
     */
    @Value("${api.version:1.0.0}")
    private String apiVersion;

    /**
     * Application environment for server configuration.
     * Used to set appropriate server URLs in documentation.
     */
    @Value("${spring.profiles.active:local}")
    private String activeProfile;

    /**
     * Security scheme name for JWT Bearer token authentication.
     * Used consistently across the API documentation for authentication references.
     */
    private static final String BEARER_AUTH_SCHEME = "bearerAuth";

    /**
     * Creates and configures the OpenAPI specification for the API.
     * 
     * This method sets up the complete OpenAPI documentation including:
     * - API metadata (title, description, version, contact information)
     * - Server configuration for different environments
     * - Security schemes for JWT Bearer token authentication
     * - Global security requirements for protected endpoints
     * 
     * @return OpenAPI specification configured for the authentication API
     * 
     * The configuration includes:
     * - Detailed API information with contact details and license
     * - JWT Bearer token security scheme for authentication
     * - Server definitions for local, development, and production environments
     * - Global security requirement applying Bearer auth to all endpoints
     * 
     * Security Integration:
     * - Defines JWT Bearer token as the primary authentication method
     * - Configures authorization header format: "Authorization: Bearer {token}"
     * - Enables interactive testing of protected endpoints in Swagger UI
     * - Provides clear instructions for API consumers on authentication
     */
    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI()
                // Configure comprehensive API information
                .info(createApiInfo())
                
                // Set up server configurations for different environments
                .servers(createServerList())
                
                // Define security components including JWT Bearer authentication
                .components(createSecurityComponents())
                
                // Apply global security requirements to all endpoints
                .addSecurityItem(createSecurityRequirement());
    }

    /**
     * Creates detailed API information for the OpenAPI specification.
     * 
     * This method configures comprehensive metadata about the API including
     * title, description, version, contact information, and licensing details.
     * The information is displayed prominently in the Swagger UI interface.
     * 
     * @return Info object containing complete API metadata
     * 
     * Information included:
     * - API title and comprehensive description
     * - Current version from application properties
     * - Contact information for API support
     * - License information for legal compliance
     * - Terms of service for API usage
     * 
     * The description provides:
     * - Overview of authentication functionality
     * - JWT token usage instructions
     * - Security best practices
     * - API endpoint categorization
     */
    private Info createApiInfo() {
        return new Info()
                .title("2uthz API Server")
                .description("""
                        # 2uthz Authentication API
                        
                        A comprehensive REST API for user authentication and authorization using JWT tokens.
                        This API provides secure user registration, login, token management, and profile operations.
                        
                        ## Authentication
                        
                        This API uses **JWT Bearer Token** authentication. To access protected endpoints:
                        
                        1. **Register** a new user account via `POST /api/auth/register`
                        2. **Login** with credentials via `POST /api/auth/login` to receive JWT tokens
                        3. **Include** the access token in the Authorization header: `Bearer {access_token}`
                        4. **Refresh** expired tokens using `POST /api/auth/refresh` with the refresh token
                        
                        ## Token Types
                        
                        - **Access Token**: Short-lived (24 hours) - used for API authentication
                        - **Refresh Token**: Long-lived (7 days) - used only for token renewal
                        
                        ## Security Features
                        
                        - ✅ **BCrypt Password Encryption** - Secure password hashing
                        - ✅ **JWT Stateless Authentication** - No server-side sessions
                        - ✅ **Token Expiration Management** - Configurable token lifespans
                        - ✅ **Input Validation** - Comprehensive request validation
                        - ✅ **Error Handling** - Secure error responses
                        
                        ## Getting Started
                        
                        1. Use the **Register** endpoint to create a new account
                        2. Use the **Login** endpoint to authenticate and receive tokens
                        3. Click the **🔒 Authorize** button above to enter your Bearer token
                        4. Test protected endpoints with automatic token inclusion
                        
                        ## API Categories
                        
                        - **Authentication**: User registration, login, and token management
                        - **User Management**: Profile operations and user data
                        - **Security**: Email validation and account security features
                        """)
                .version(apiVersion)
                .contact(createContactInfo())
                .license(createLicenseInfo())
                .termsOfService("https://example.com/terms");
    }

    /**
     * Creates contact information for the API documentation.
     * 
     * This method provides contact details for API users who need support,
     * have questions, or want to report issues with the API.
     * 
     * @return Contact object with support information
     * 
     * Contact information includes:
     * - Support team name and contact details
     * - Official support email address
     * - API documentation and support website
     * 
     * This information helps API consumers:
     * - Get technical support for integration issues
     * - Report bugs or security vulnerabilities
     * - Request new features or enhancements
     * - Access additional documentation and resources
     */
    private Contact createContactInfo() {
        return new Contact()
                .name("2uthz API Support Team")
                .email("support@2uthz.com")
                .url("https://2uthz.com/api-docs");
    }

    /**
     * Creates license information for the API documentation.
     * 
     * This method defines the licensing terms under which the API is made available.
     * It provides legal clarity for API consumers regarding usage rights and restrictions.
     * 
     * @return License object with legal information
     * 
     * License details include:
     * - License type and version
     * - Link to full license text
     * - Usage rights and restrictions
     * 
     * Common license types:
     * - MIT License: Permissive open source license
     * - Apache 2.0: Popular enterprise-friendly license
     * - Proprietary: Custom license for commercial APIs
     */
    private License createLicenseInfo() {
        return new License()
                .name("MIT License")
                .url("https://opensource.org/licenses/MIT");
    }

    /**
     * Creates server configuration list for different deployment environments.
     * 
     * This method configures server URLs for various environments where the API
     * is deployed, allowing users to test against different instances from the
     * same Swagger UI interface.
     * 
     * @return List of Server objects representing different deployment environments
     * 
     * Server configurations include:
     * - Local development server (localhost:8080)
     * - Development environment server
     * - Staging environment server (optional)
     * - Production environment server
     * 
     * Each server includes:
     * - Base URL for API requests
     * - Descriptive name for environment identification
     * - Environment-specific configuration notes
     * 
     * Benefits:
     * - Easy environment switching in Swagger UI
     * - Consistent API testing across environments
     * - Clear documentation of deployment endpoints
     * - Support for multi-environment development workflows
     */
    private List<Server> createServerList() {
        return List.of(
                // Local development server
                new Server()
                        .url("http://localhost:8080")
                        .description("Local Development Server")
                        .variables(null),
                
                // Development environment server
                new Server()
                        .url("https://dev-api.2uthz.com")
                        .description("Development Environment")
                        .variables(null),
                
                // Production environment server
                new Server()
                        .url("https://api.2uthz.com")
                        .description("Production Environment")
                        .variables(null)
        );
    }

    /**
     * Creates security components for JWT Bearer token authentication.
     * 
     * This method configures the security schemes available for API authentication,
     * specifically setting up JWT Bearer token authentication for protected endpoints.
     * 
     * @return Components object containing security scheme definitions
     * 
     * Security scheme configuration:
     * - Scheme type: HTTP Bearer authentication
     * - Bearer format: JWT token format
     * - Authorization header: "Authorization: Bearer {token}"
     * - Token source: Obtained from login/register endpoints
     * 
     * The security scheme enables:
     * - Interactive token testing in Swagger UI
     * - Automatic token inclusion in API requests
     * - Clear documentation of authentication requirements
     * - Consistent security implementation across endpoints
     * 
     * JWT Bearer Token Flow:
     * 1. User authenticates via login endpoint
     * 2. Server returns access and refresh tokens
     * 3. Client includes access token in Authorization header
     * 4. Server validates token and processes request
     * 5. Client refreshes token when expired using refresh token
     */
    private Components createSecurityComponents() {
        return new Components()
                .addSecuritySchemes(BEARER_AUTH_SCHEME, 
                    new SecurityScheme()
                            .type(SecurityScheme.Type.HTTP)
                            .scheme("bearer")
                            .bearerFormat("JWT")
                            .description("""
                                    **JWT Bearer Token Authentication**
                                    
                                    Enter your JWT access token received from the login or register endpoints.
                                    
                                    **Format**: `Bearer {your-jwt-access-token}`
                                    
                                    **Example**: `Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...`
                                    
                                    **How to get a token**:
                                    1. Use the **POST /api/auth/register** endpoint to create an account
                                    2. Or use the **POST /api/auth/login** endpoint with existing credentials
                                    3. Copy the `accessToken` from the response
                                    4. Click the 🔒 **Authorize** button above
                                    5. Enter: `Bearer {your-access-token}`
                                    6. Click **Authorize** to apply to all requests
                                    
                                    **Token Management**:
                                    - Access tokens expire in 24 hours
                                    - Use **POST /api/auth/refresh** to get new tokens
                                    - Refresh tokens are valid for 7 days
                                    - Always use the latest access token for API calls
                                    """)
                );
    }

    /**
     * Creates global security requirement for JWT Bearer authentication.
     * 
     * This method defines the default security requirement that applies to all
     * API endpoints unless explicitly overridden. It ensures that protected
     * endpoints are clearly documented as requiring authentication.
     * 
     * @return SecurityRequirement object specifying JWT Bearer authentication
     * 
     * Security requirement configuration:
     * - Applies Bearer token authentication globally
     * - Can be overridden per endpoint with @SecurityRequirement annotations
     * - Provides consistent security documentation across the API
     * - Enables automatic token inclusion in Swagger UI requests
     * 
     * Override behavior:
     * - Public endpoints can override with @SecurityRequirement(name = "")
     * - Protected endpoints inherit the global requirement automatically
     * - Custom security requirements can be added per endpoint
     * - Multiple security schemes can be combined if needed
     * 
     * Benefits:
     * - Consistent security documentation
     * - Reduced boilerplate in endpoint annotations
     * - Clear indication of authentication requirements
     * - Improved API security understanding for consumers
     */
    private SecurityRequirement createSecurityRequirement() {
        return new SecurityRequirement()
                .addList(BEARER_AUTH_SCHEME);
    }
}
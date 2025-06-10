package com._uthz.api_server.security;

import com._uthz.api_server.entity.User;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * Custom UserDetails implementation for JWT-based authentication.
 * 
 * This class implements Spring Security's UserDetails interface to provide
 * user information and authorities for JWT-authenticated users. It wraps
 * our User entity and provides the necessary methods for Spring Security
 * authentication and authorization.
 */
@RequiredArgsConstructor
@Getter
public class JwtUserDetails implements UserDetails {

    private final Long userId;
    private final String email;
    private final String nickname;
    private final String role;
    private final String jwtToken;

    public static JwtUserDetails fromUser(User user, String jwtToken) {
        return new JwtUserDetails(
            user.getUserId(),
            user.getEmail(),
            user.getNickname(),
            user.getRole(),
            jwtToken
        );
    }

    public static JwtUserDetails fromTokenClaims(Long userId, String email, String nickname, 
                                                String role, String jwtToken) {
        return new JwtUserDetails(userId, email, nickname, role, jwtToken);
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        List<SimpleGrantedAuthority> authorities = new ArrayList<>();
        
        String userRole = (role != null && !role.trim().isEmpty()) ? role.trim() : "USER";
        
        switch (userRole.toUpperCase()) {
            case "ADMIN":
                authorities.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
                authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
                break;
                
            case "MODERATOR":
                authorities.add(new SimpleGrantedAuthority("ROLE_MODERATOR"));
                authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
                break;
                
            case "USER":
            default:
                authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
                break;
        }
        
        return authorities;
    }

    @Override
    public String getPassword() {
        return null;
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    public boolean hasRole(String roleName) {
        return role != null && role.equalsIgnoreCase(roleName);
    }

    public boolean isAdmin() {
        return hasRole("ADMIN");
    }

    public boolean isModerator() {
        return hasRole("MODERATOR");
    }

    @Override
    public String toString() {
        return String.format("JwtUserDetails{userId=%d, email='%s', nickname='%s', role='%s'}", 
                           userId, email, nickname, role);
    }
}
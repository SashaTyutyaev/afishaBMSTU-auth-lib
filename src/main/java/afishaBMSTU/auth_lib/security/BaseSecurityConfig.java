package afishaBMSTU.auth_lib.security;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableMethodSecurity
@RequiredArgsConstructor
public abstract class BaseSecurityConfig {

    private final BaseAuthTokenFilter<?> authTokenFilter;

    /**
     * Configures the security filter chain.
     *
     * @param http the HttpSecurity object to configure
     * @return the configured SecurityFilterChain
     * @throws Exception if an error occurs during configuration
     */
    @Bean
    public SecurityFilterChain baseFilterChain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/swagger-ui/**", "/v3/api-docs/**").permitAll()
                );

        configureHttpSecurity(http);

        anyRequestConfiguration(http);

        http.addFilterBefore(authTokenFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    /**
     * Override this method to add custom HTTP security configurations.
     *
     * @param http the HttpSecurity object to configure
     * @throws Exception if an error occurs during configuration
     */
    protected void configureHttpSecurity(HttpSecurity http) throws Exception {
        // Override this method to add custom configuration
    }

    /**
     * Configures the security settings for any other requests.
     *
     * @param http the HttpSecurity object to configure
     * @throws Exception if an error occurs during configuration
     */
    protected void anyRequestConfiguration(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth -> auth
                .anyRequest().authenticated() // Require authentication for any other requests
        );
    }
}

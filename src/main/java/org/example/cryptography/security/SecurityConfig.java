package org.example.cryptography.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .headers(headers -> headers.frameOptions().sameOrigin())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/register",  // Vaadin route (not enough by itself!)
                                "/login",
                                "/logout",
                                "/vaadin/**",
                                "/frontend/**",
                                "/webjars/**",
                                "/images/**",
                                "/h2-console/**",
                                "/frontend-es6/**",
                                "/frontend-es5/**",
                                "/VAADIN/**"
                        ).permitAll()
                        .requestMatchers("/**").permitAll()  // ❗разрешает доступ ко всем Vaadin страницам (нужно контролировать внутри)
                        .anyRequest().authenticated()
                )
                .formLogin(form -> form
                        .loginPage("/login")
                        .permitAll()
                )
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessUrl("/login?logout")
                        .permitAll()
                );

        return http.build();
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}

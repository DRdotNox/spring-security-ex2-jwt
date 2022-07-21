package com.security.config.security;


import com.security.config.security.jwt.filter.JwtTokenValidator;
import com.security.config.security.jwt.filter.JwtUsernamePasswordAuthFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import static com.security.UserRoles.ADMIN;
import static com.security.UserRoles.MODERATOR;
import static com.security.UserRoles.USER;


/* до  02.21.2022 (v5.7.0-M2)  */
@Configuration
@EnableWebSecurity
//@EnableGlobalMethodSecurity(prePostEnabled = true) // ???
public class AppConfig extends WebSecurityConfigurerAdapter {



    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(10);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http
                .cors().disable()
                .csrf().disable();

       http.authorizeRequests()
               .antMatchers( "/api/v1/auth").permitAll()
               .and()
                .addFilterBefore(new JwtUsernamePasswordAuthFilter(authenticationManager()), UsernamePasswordAuthenticationFilter.class)
               .addFilterAfter(new JwtTokenValidator(), JwtUsernamePasswordAuthFilter.class)
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    }


    @Bean
    @Override
    protected UserDetailsService userDetailsService() {
        UserDetails adminUser = User.builder() // <- User - классическая реализация UserDetails. можно расширить, имплементировав этот интерфейс.
                .username("admin")
                .password(passwordEncoder().encode("12431243!"))
                .roles(ADMIN.name()) // <- конвертнется в ROLE_ADMIN
                .authorities(ADMIN.getGrantedAuthorities())
                .build();

        UserDetails simpleUser = User.builder() // <- User - классическая реализация UserDetails. можно расширить, имплементировав этот интерфейс.
                .username("user")
                .password(passwordEncoder().encode("12431243!"))
                .roles(USER.name()) // <- конвертнется в ROLE_ADMIN
                .authorities(USER.getGrantedAuthorities())
                .build();

        UserDetails simpleModerator = User.builder() // <- User - классическая реализация UserDetails. можно расширить, имплементировав этот интерфейс.
                .username("moderator")
                .password(passwordEncoder().encode("12431243!"))
                .roles(MODERATOR.name()) // <- конвертнется в ROLE_ADMIN
                .authorities(MODERATOR.getGrantedAuthorities())
                .build();

        return new InMemoryUserDetailsManager( //create breakpoint to see permissions
                adminUser,
                simpleUser,
                simpleModerator
        );

    }
}


///* после  02.21.2022 (v5.7.0-M2)  */
//@Configuration
//@EnableWebSecurity
//public class AppConfig  extends WebSecurityConfiguration {
//}
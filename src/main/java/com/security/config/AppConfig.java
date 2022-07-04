package com.security.config;


import com.security.UserRoles;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;


/* до  02.21.2022 (v5.7.0-M2)  */
@Configuration
@EnableWebSecurity
public class AppConfig  extends WebSecurityConfigurerAdapter {


    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(10);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http

                .authorizeRequests()
                .antMatchers("/api/v1/public/**")
                .permitAll()
                .antMatchers("/api/v1/admin/**")
                .hasRole(UserRoles.ADMIN.name())
                .anyRequest()
                .authenticated()
                .and()
                .httpBasic();
    }

    @Bean
    @Override
    protected UserDetailsService userDetailsService() {
        UserDetails adminUser = User.builder() // <- User - классическая реализация UserDetails. можно расширить, имплементировав этот интерфейс.
                .username("admin")
                .password(passwordEncoder().encode("adminpass123"))
                .roles(UserRoles.ADMIN.name()) // <- конвертнется в ROLE_ADMIN
                .build();

        UserDetails simpleUser = User.builder() // <- User - классическая реализация UserDetails. можно расширить, имплементировав этот интерфейс.
                .username("user")
                .password(passwordEncoder().encode("userpass123"))
                .roles(UserRoles.USER.name()) // <- конвертнется в ROLE_ADMIN
                .build();

        return new InMemoryUserDetailsManager(
                adminUser,
                simpleUser
        );

    }
}







///* после  02.21.2022 (v5.7.0-M2)  */
//@Configuration
//@EnableWebSecurity
//public class AppConfig  extends WebSecurityConfiguration {
//}
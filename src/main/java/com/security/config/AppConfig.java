package com.security.config;


import com.security.UserPermissions;
import com.security.UserRoles;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.lang.UsesSunMisc;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import static com.security.UserRoles.*;


/* до  02.21.2022 (v5.7.0-M2)  */
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true) // ???
public class AppConfig  extends WebSecurityConfigurerAdapter {


    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(10);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http.csrf().disable();

        http

                .authorizeRequests()
                .antMatchers("/api/v1/public/**")
                .permitAll()
                .antMatchers("/api/v1/admin/**")
                .hasRole(ADMIN.name())
//                .antMatchers(HttpMethod.DELETE, "/api/v1/user/**").hasAuthority(UserPermissions.USER_WRITE.getPermission())
//                .antMatchers(HttpMethod.POST, "/api/v1/user/**").hasAuthority(UserPermissions.USER_WRITE.getPermission())
//                .antMatchers(HttpMethod.PUT, "/api/v1/user/**").hasAuthority(UserPermissions.USER_WRITE.getPermission())
//                .antMatchers(HttpMethod.GET, "/api/v1/user/**").hasAnyRole(USER.name(), MODERATOR.name())
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
package org.test.springsecuritytests.securityConfig;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;


@Configuration
@EnableWebSecurity
public class MultiHttpSecurityConfig {


    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth)
            throws Exception {
        auth
                .inMemoryAuthentication()
                .withUser("user").password("password").roles("USER");
    }

    @Configuration
    @Order(1)
    public static class ApiWebSecurityConfigurationAdapter extends WebSecurityConfigurerAdapter {
        protected void configure(HttpSecurity http) throws Exception {
            http
                    .authorizeRequests()
                    .antMatchers("/", "/home", "/login").permitAll()
                    .anyRequest().authenticated()
                    .and()
                    .httpBasic()


                    .and().exceptionHandling().authenticationEntryPoint(unauthorizedEntryPoint());
        }
    }

    @Bean
    public static AuthenticationEntryPoint unauthorizedEntryPoint() {
        return (request, response, authException) -> response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
    }

    @Bean
    public AuthenticationFailureHandler handleAuthenticationFailure() {
        return new SimpleUrlAuthenticationFailureHandler() {

            @Override
            public void onAuthenticationFailure(HttpServletRequest httpRequest, HttpServletResponse httpResponse,
                                                AuthenticationException authenticationException) throws IOException, ServletException {

                // custom failure code here
                setDefaultFailureUrl("/login");
                super.onAuthenticationFailure(httpRequest, httpResponse, authenticationException);
            }
        };}

        @Configuration
        @Order(2)
        public static class FormLoginWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {
//        @Override
//        public void configure(WebSecurity web) throws Exception {
//            web
//                    .ignoring()
//                    .antMatchers("/resources/**");
//        }

            @Override
            protected void configure(HttpSecurity http) throws Exception {
                http
                        .authorizeRequests()
                        .antMatchers("/", "/home").permitAll()
                        .anyRequest().hasRole("USER")
                        .and()
                        .formLogin()
                        .loginPage("/login")
                        .permitAll();
            }

            @Bean
            public PasswordEncoder passwordEncoder() {
                return NoOpPasswordEncoder.getInstance();
            }
        }
    }



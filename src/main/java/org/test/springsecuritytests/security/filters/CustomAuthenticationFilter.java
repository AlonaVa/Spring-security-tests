package org.test.springsecuritytests.security.filters;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.test.springsecuritytests.security.authentication.CustomAuthentication;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
@ComponentScan(value = "org.test.springsecuritytests")
public class CustomAuthenticationFilter extends OncePerRequestFilter {

    @Autowired
    private AuthenticationManager manager;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException, UsernameNotFoundException {
        String user = request.getHeader("Authorization");
        var username = request.getHeader("username");
        var password = request.getHeader("password");
        if (user == null) {
            //use formLogin()
        } else {
            Authentication basicAuthentication = new CustomAuthentication(username, password);
            Authentication authResult = manager.authenticate(basicAuthentication);
            if (authResult.isAuthenticated()) {
                SecurityContextHolder.getContext().setAuthentication(authResult);
            }
        }

        filterChain.doFilter(request, response);
    }


    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        return request.getServletPath().equals("/login") || request.getServletPath().equals("/") || request.getServletPath().equals("/home");
    }

}

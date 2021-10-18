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

import javax.servlet.*;
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
        String user = request.getHeader("user");
        String password = request.getHeader("password");

        CustomAuthentication customAuthentication = new CustomAuthentication(user, password); // (Object principal, Object credentials)
        Authentication authResult = manager.authenticate(customAuthentication);
        if (authResult.isAuthenticated()) {
            // If I have fully authentication instance, add to the security context
            // do not think about the security context for now.
            SecurityContextHolder.getContext().setAuthentication(authResult);


            filterChain.doFilter(request, response);
        }
    }

//    @Override
//    public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain) throws IOException, ServletException {
//        HttpServletRequest request = (HttpServletRequest) req;
//        HttpServletResponse response = (HttpServletResponse) resp;
//        String user = request.getHeader("user");
//        String password = request.getHeader("password");
//
//        CustomAuthentication customAuthentication = new CustomAuthentication(user, password); // (Object principal, Object credentials)
//        Authentication authResult = manager.authenticate(customAuthentication);
//        if (authResult.isAuthenticated()) {
//            // If I have fully authentication instance, add to the security context
//            // do not think about the security context for now.
//            SecurityContextHolder.getContext().setAuthentication(authResult);
//
//
//            chain.doFilter(req, resp);
//        }
//    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        return request.getServletPath().equals("/login")||request.getServletPath().equals("/")||request.getServletPath().equals("/home");
    }

}

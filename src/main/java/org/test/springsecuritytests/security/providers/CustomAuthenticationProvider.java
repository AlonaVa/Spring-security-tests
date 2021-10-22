//package org.test.springsecuritytests.security.providers;
//
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.context.annotation.ComponentScan;
//import org.springframework.security.authentication.AuthenticationProvider;
//import org.springframework.security.authentication.BadCredentialsException;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.core.AuthenticationException;
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.security.core.userdetails.UserDetailsService;
//import org.springframework.security.crypto.password.PasswordEncoder;
//import org.springframework.stereotype.Component;
//import org.test.springsecuritytests.security.authentication.CustomAuthentication;
//
//
//@Component
//@ComponentScan(value = "org.test.springsecuritytests")
//public class CustomAuthenticationProvider implements AuthenticationProvider {
//
//
//    @Autowired
//    private UserDetailsService userDetailsService;
//
//    @Autowired
//    private PasswordEncoder passwordEncoder;
//
//    @Override
//    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
//        // implement authentication logic
//
//        // if the request is authentication you should return here
//        // an fully authenticated Authentication instance
//
//        // if the request is not authenticated you should throw AuthenticationException
//
//        // the Authentication isn't supported by this AP -> return null
//        String username = authentication.getName();
//        String password = String.valueOf(authentication.getCredentials());
//
//        UserDetails u = userDetailsService.loadUserByUsername(username);
//        if (u != null) {
//            if (passwordEncoder.matches(password, u.getPassword())) {
//                var a = new CustomAuthentication(username, password, u.getAuthorities());
//                return a;
//            }
//        }
//        throw new BadCredentialsException("Error!");
//    }
//
//    @Override
//    public boolean supports(Class<?> authType) {// type of Authentication
//        return CustomAuthentication.class.equals(authType);
//    }
//}

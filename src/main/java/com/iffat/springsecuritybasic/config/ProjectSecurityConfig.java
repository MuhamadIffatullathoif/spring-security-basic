package com.iffat.springsecuritybasic.config;

import com.iffat.springsecuritybasic.filter.CsrfCookieFilter;
import com.iffat.springsecuritybasic.filter.RequestValidationBeforeFilter;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.support.BeanDefinitionRegistryPostProcessor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.AbstractSecurityWebApplicationInitializer;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.debug.DebugFilter;
import org.springframework.security.web.firewall.HttpFirewall;
import org.springframework.security.web.firewall.RequestRejectedHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.filter.CompositeFilter;

import java.io.IOException;
import java.util.Collections;
import java.util.List;

@Configuration
@EnableWebSecurity(debug = true)
public class ProjectSecurityConfig {

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {

        CsrfTokenRequestAttributeHandler requestHandler = new CsrfTokenRequestAttributeHandler();
        requestHandler.setCsrfRequestAttributeName("_csrf");

        /*
         * Below is the custom security configuration
         */

        http
                .securityContext(sec -> sec
                        .requireExplicitSave(false))
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.ALWAYS))
                .cors(corsConfig -> corsConfig.configurationSource(new CorsConfigurationSource() {
                    @Override
                    public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
                        CorsConfiguration config = new CorsConfiguration();
                        config.setAllowedOrigins(Collections.singletonList("http://localhost:4200"));
                        config.setAllowedMethods(Collections.singletonList("*"));
                        config.setAllowCredentials(true);
                        config.setAllowedHeaders(Collections.singletonList("*"));
                        config.setMaxAge(3600L);
                        return config;
                    }
                }))
                .csrf(csrf -> csrf
                        .csrfTokenRequestHandler(requestHandler)
                        .ignoringRequestMatchers("/contact", "/register")
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
                .addFilterAfter(new CsrfCookieFilter(), BasicAuthenticationFilter.class)
                .addFilterBefore(new RequestValidationBeforeFilter(), BasicAuthenticationFilter.class)
                .authorizeHttpRequests(auth -> auth
//                        .requestMatchers("/myAccount").hasAuthority("VIEWACCOUNT")
//                        .requestMatchers("/myBalance").hasAnyAuthority("VIEWACCOUNT", "VIEWBALANCE")
//                        .requestMatchers("/myLoans").hasAuthority("VIEWLOANS")
//                        .requestMatchers("/myCards").hasAuthority("VIEWCARDS")
                        .requestMatchers("/myAccount").hasRole("USER")
                        .requestMatchers("/myBalance").hasAnyRole("USER", "ADMIN")
                        .requestMatchers("/myLoans").hasRole("USER")
                        .requestMatchers("/myCards").hasRole("USER")
                        .requestMatchers("/user").authenticated()
                        .requestMatchers("/notices", "/contact", "/register").permitAll())
                .formLogin(Customizer.withDefaults())
                .httpBasic(Customizer.withDefaults());
        return http.build();
    }

//    @Bean
//    public InMemoryUserDetailsManager userDetailsService() {
//        /*
//         * Approach 1 where we use withDefaultPasswordEncoder() method
//         * While creating the user details
//         */
////        UserDetails admin = User.withDefaultPasswordEncoder()
////                .username("admin")
////                .password("12345")
////                .authorities("admin")
////                .build();
////        UserDetails user = User.withDefaultPasswordEncoder()
////                .username("user")
////                .password("12345")
////                .authorities("read")
////                .build();
////        return new InMemoryUserDetailsManager(admin, user);
//        /*
//         * Approach 2 where we use NoOpPasswordEncoder Bean
//         * While creating the user details
//         * */
//        UserDetails admin = User.withUsername("admin")
//                .password("12345")
//                .authorities("admin")
//                .build();
//        UserDetails user = User.withUsername("user")
//                .password("12345")
//                .authorities("read")
//                .build();
//        return new InMemoryUserDetailsManager(admin, user);
//    }

//    @Bean
//    public UserDetailsService userDetailsService(DataSource dataSource) {
//        return new JdbcUserDetailsManager(dataSource);
//    }

    /*
     * No recommended on production NoOpPasswordEncoder
     * */

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    static BeanDefinitionRegistryPostProcessor beanDefinitionRegistryPostProcessor() {
        return registry -> registry.getBeanDefinition(AbstractSecurityWebApplicationInitializer.DEFAULT_FILTER_NAME).setBeanClassName(CompositeFilterChainProxy.class.getName());
    }

    static class CompositeFilterChainProxy extends FilterChainProxy {

        private final Filter doFilterDelegate;

        private final FilterChainProxy springSecurityFilterChain;

        CompositeFilterChainProxy(List<? extends Filter> filters) {
            this.doFilterDelegate = createDoFilterDelegate(filters);
            this.springSecurityFilterChain = findFilterChainProxy(filters);
        }

        @Override
        public void afterPropertiesSet() {
            this.springSecurityFilterChain.afterPropertiesSet();
        }

        @Override
        public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
                throws IOException, ServletException {
            this.doFilterDelegate.doFilter(request, response, chain);
        }

        @Override
        public List<Filter> getFilters(String url) {
            return this.springSecurityFilterChain.getFilters(url);
        }

        @Override
        public List<SecurityFilterChain> getFilterChains() {
            return this.springSecurityFilterChain.getFilterChains();
        }

        @Override
        public void setSecurityContextHolderStrategy(SecurityContextHolderStrategy securityContextHolderStrategy) {
            this.springSecurityFilterChain.setSecurityContextHolderStrategy(securityContextHolderStrategy);
        }

        @Override
        public void setFilterChainValidator(FilterChainValidator filterChainValidator) {
            this.springSecurityFilterChain.setFilterChainValidator(filterChainValidator);
        }

        @Override
        public void setFilterChainDecorator(FilterChainDecorator filterChainDecorator) {
            this.springSecurityFilterChain.setFilterChainDecorator(filterChainDecorator);
        }

        @Override
        public void setFirewall(HttpFirewall firewall) {
            this.springSecurityFilterChain.setFirewall(firewall);
        }

        @Override
        public void setRequestRejectedHandler(RequestRejectedHandler requestRejectedHandler) {
            this.springSecurityFilterChain.setRequestRejectedHandler(requestRejectedHandler);
        }

        private static Filter createDoFilterDelegate(List<? extends Filter> filters) {
            CompositeFilter delegate = new CompositeFilter();
            delegate.setFilters(filters);
            return delegate;
        }

        private static FilterChainProxy findFilterChainProxy(List<? extends Filter> filters) {
            for (Filter filter : filters) {
                if (filter instanceof FilterChainProxy fcp ) {
                    return fcp;
                }
                if (filter instanceof DebugFilter debugFilter ) {
                    return debugFilter.getFilterChainProxy();
                }
            }
            throw new IllegalStateException("Couldn't find FilterChainProxy in " + filters);
        }

    }
}

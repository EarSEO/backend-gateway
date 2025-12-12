package com.earseo.gateway.security;

import com.earseo.gateway.common.exception.AuthError;
import com.earseo.gateway.common.exception.BaseException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerExceptionResolver;

import java.util.List;

@Component
public class SwaggerFilter extends OncePerRequestFilter {

    @Value("${allowed.hosts}")
    private List<String> allowedHosts;
    private final HandlerExceptionResolver resolver;

    private static final AntPathMatcher pathMatcher = new AntPathMatcher();

    public SwaggerFilter( @Qualifier("handlerExceptionResolver") HandlerExceptionResolver resolver) {
        this.resolver = resolver;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) {

        try {
            String host = request.getHeader("Host");

            if (host == null || !isAllowedHost(host)) {
                throw new BaseException(AuthError.DISALLOWED_HOST);
            }

            filterChain.doFilter(request, response);

        } catch (Exception e) {
            resolver.resolveException(request, response, null, e);
        }
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();

        return !pathMatcher.match("/swagger-ui/**", path) &&
                !pathMatcher.match("/swagger-ui.html", path) &&
                !pathMatcher.match("/**/api-docs", path) &&
                !pathMatcher.match("/api-docs/**", path);
    }

    private boolean isAllowedHost(String host) {
        //port 제거
        String hostname = host.split(":")[0];

        return allowedHosts.stream()
                .anyMatch(hostname::equals);
    }
}

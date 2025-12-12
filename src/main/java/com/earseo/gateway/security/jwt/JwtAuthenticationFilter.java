package com.earseo.gateway.security.jwt;

import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerExceptionResolver;

import java.io.IOException;
import java.util.*;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    @Value("${security.path.public}")
    private String publicPath;
    @Value("${security.path.auth}")
    private String authPath;
    private final JwtValidator jwtValidator;
    private final HandlerExceptionResolver resolver;
    private static final AntPathMatcher pathMatcher = new AntPathMatcher();

    public JwtAuthenticationFilter(JwtValidator jwtValidator, @Qualifier("handlerExceptionResolver") HandlerExceptionResolver resolver) {
        this.jwtValidator = jwtValidator;
        this.resolver = resolver;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String jwtToken = jwtValidator.getTokenFromRequest(request);

        if (jwtToken != null) {
            try {
                Claims claims = jwtValidator.validateToken(jwtToken);
                String userId = claims.getSubject();
                String role = claims.get("role", String.class);

                List<GrantedAuthority> authorities = Collections.singletonList(
                        new SimpleGrantedAuthority(role)
                );

                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(userId, null, authorities);
                SecurityContextHolder.getContext().setAuthentication(authentication);

                MutableHttpServletRequest mutableRequest = new MutableHttpServletRequest(request);
                mutableRequest.putHeader("X-USER-ID", userId);
                mutableRequest.putHeader("X-USER-ROLE", role);

                filterChain.doFilter(mutableRequest, response);
                return;
            } catch (Exception e) {
                resolver.resolveException(request, response, null, e);
                return;
            }
        }
        filterChain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        String[] publicPaths = publicPath.split(",");
        String[] authPaths = authPath.split(",");

        for (String pattern : authPaths) {
            if (pathMatcher.match(pattern, path)) {
                return false;
            }
        }

        for (String pattern : publicPaths) {
            if (pathMatcher.match(pattern, path)) {
                return true;
            }
        }

        return false;
    }

    private static class MutableHttpServletRequest extends HttpServletRequestWrapper {
        private final Map<String, String> headers = new HashMap<>();

        public MutableHttpServletRequest(HttpServletRequest request) {
            super(request);
        }

        public void putHeader(String name, String value) {
            headers.put(name, value);
        }

        @Override
        public String getHeader(String name) {
            return headers.getOrDefault(name, super.getHeader(name));
        }

        @Override
        public Enumeration<String> getHeaders(String name) {
            return headers.containsKey(name)
                    ? Collections.enumeration(Collections.singletonList(headers.get(name)))
                    : super.getHeaders(name);
        }

        @Override
        public Enumeration<String> getHeaderNames() {
            Set<String> names = new HashSet<>(headers.keySet());
            names.addAll(Collections.list(super.getHeaderNames()));
            return Collections.enumeration(names);
        }
    }
}


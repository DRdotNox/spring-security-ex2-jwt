package com.security.config.security.filter;

import lombok.extern.slf4j.Slf4j;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
@Order(0)
@Slf4j
public class CustomFilter extends GenericFilterBean {


    @Override
    public void doFilter(ServletRequest servletRequest,
                         ServletResponse servletResponse,
                         FilterChain filterChain) throws IOException, ServletException {

        log.info("Custom filter init");
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;

        String authHeader = request.getHeader("X-Auth-Token");

        if (authHeader == null || !authHeader.startsWith("Token")) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Authorization header needed");
        }

        filterChain.doFilter(servletRequest, servletResponse);

        log.info("Custom filter destroy");
    }
}

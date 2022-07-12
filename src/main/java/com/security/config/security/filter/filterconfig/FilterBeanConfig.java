package com.security.config.security.filter.filterconfig;

import com.security.config.security.filter.CustomFilter;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class FilterBeanConfig {
    @Bean
    public FilterRegistrationBean<CustomFilter> requestMemeFilter() {
        CustomFilter memeFilter=new CustomFilter();
        final FilterRegistrationBean<CustomFilter> reg = new FilterRegistrationBean(memeFilter);
        reg.addUrlPatterns("/*");
        reg.setOrder(1); //defines filter execution order
        return reg;
    }

}
package ru.ratauth.server

import groovy.util.logging.Slf4j
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.builder.SpringApplicationBuilder
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.ComponentScan
import ratpack.spring.config.EnableRatpack
import ru.ratauth.server.configuration.RatAuthProperties

@Slf4j
@SpringBootApplication
@EnableRatpack
@ComponentScan(["ru.ratauth"])
@EnableConfigurationProperties(RatAuthProperties.class)
public class RatAuthApplication {
  public static final int DEFAULT_PADDING = 50

  public static void main(String[] args) {
    log.debug 'Starting'.center(DEFAULT_PADDING, '=')
    new SpringApplicationBuilder(RatAuthApplication.class)
        .web(false)
        .run(args);
    log.debug 'Started'.center(DEFAULT_PADDING, '=')
  }



}
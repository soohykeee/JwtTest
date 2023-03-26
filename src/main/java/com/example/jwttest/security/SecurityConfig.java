package com.example.jwttest.security;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.io.IOException;
import java.util.List;

@Configuration
@RequiredArgsConstructor
@EnableWebSecurity
public class SecurityConfig {

    private final JwtProvider jwtProvider;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                // ID, password 문자열을 Base64로 인코딩하여 전달하는 구조
                .httpBasic().disable()
                // Cookie 기반 인증이 아닌, JWT 기반 인증이기에 csrf 사용 X
                .csrf().disable()
                // CORS 설정
                .cors(c -> {
                    CorsConfigurationSource source = request -> {
                        // cors 허용 패턴
                        CorsConfiguration config = new CorsConfiguration();

                        config.setAllowedOrigins(List.of("*"));
                        config.setAllowedMethods(List.of("*"));

                        return config;
                    };
                    c.configurationSource(source);
                })
                // Spring Security Session 정책 -> Session 생성 및 사용 X
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()

                // 조건 별 요청 허용 or 제한 설정
                .authorizeHttpRequests()
                // register (회원가입), login (로그인) 에는 모두가 접근이 가능하도록 허용
                .requestMatchers("/register", "/login", "/refresh").permitAll()
                // admin 관련 페이지는 ADMIN 권한인 유저만 접근 가능
                .requestMatchers("/admin/**").hasRole("ADMIN")
                // user 관련 페이지는 USER 권한인 유저만 접근 가능
                .requestMatchers("/user/**").hasRole("USER")
                // 위 외의 요청들은 모두 거부
                .anyRequest().denyAll()
                .and()

                // addFilterBefore(A, B) -> A가 B보다 먼저 실행
                // 즉, JWT 인증 필터를 적용
                .addFilterBefore(new JwtAuthenticationFilter(jwtProvider), UsernamePasswordAuthenticationFilter.class)
                // Exception handling 추가
                .exceptionHandling()
                .accessDeniedHandler(new AccessDeniedHandler() {
                    @Override
                    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
                        // 권한 문제 발생시
                        response.setStatus(403);
                        response.setCharacterEncoding("utf-8");
                        response.setContentType("text/html; charset=UTF-8");
                        response.getWriter().write("권한이 없는 사용자입니다.");
                    }
                })

                .authenticationEntryPoint(new AuthenticationEntryPoint() {
                    @Override
                    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
                        // 인증 문제 발생 시
                        response.setStatus(401);
                        response.setCharacterEncoding("utf-8");
                        response.setContentType("text/html; charset=UTF-8");
                        response.getWriter().write("인증되지 않은 사용자입니다.");
                    }
                });

        return http.build();
    }

    /*
     .addFilterBefore(new JwtAuthenticationFilter(jwtProvider), UsernamePasswordAuthenticationFilter.class)
      -> 해당 부분을 작성해주었는데, 앞서 우리는 JWT를 검증하기 위한 Filter인 JwtAuthenticationFilter 를 생성해주었다.
      그렇다면, 해당 필터 적용은 언제 해주어야 바람직할까??

      기본적으로 인증을 처리하는 기본 필터는 UsernamePasswordAuthenticationFilter 이다.
      그렇기에, 별도의 인증 로직을 가진 필터를 추가해주고 싶다면, 해당 필터 앞에 추가해주는 설정이 필요하다.

     */

    /*
    createDelegatingPasswordEncoder() 로 설정 시
     -> {noop}abcdef~!@#$% ... 처럼 password의 앞에 Enocoding 방식이 붙은채로 암호화 방식을 지정하여 저장이 가능
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
}

package com.furkan.security.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;//Tek Seferlik İşlem - Filtreleme - Güvenlik - Loglama

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String userEmail;
        if (authHeader != null || authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request,response);
            return;
        }
        jwt = authHeader.substring(7); //7 den sonrası alınır çünkü bearer yazan yer atılır.
        userEmail = jwtService.extractUsername(jwt); // her şey userEmail'i JWT belirtecinden çıkarıyor

    }
}





//ServletException => API ile ilgili hataları gösterir
//IOException => IO işlemlerinde örenğin ağ bağlantısı kurma , dosya okuma yazma işlemlerinde filan

//@RequiredArgsConstructor => final alanları constructor oluştur.
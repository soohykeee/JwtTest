package com.example.jwttest.member;

import com.example.jwttest.member.dto.SignRequest;
import com.example.jwttest.member.dto.SignResponse;
import com.example.jwttest.security.JwtProvider;
import com.example.jwttest.security.Token;
import com.example.jwttest.security.TokenDto;
import com.example.jwttest.security.TokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;
import java.util.UUID;

@Service
@Transactional
@RequiredArgsConstructor
public class SignService {

    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtProvider jwtProvider;
    private final TokenRepository tokenRepository;

    public SignResponse login(SignRequest request) throws Exception {
        Member member = memberRepository.findByAccount(request.getAccount()).orElseThrow(() -> new UsernameNotFoundException("계정 정보를 확인해주세요."));

        if (!passwordEncoder.matches(request.getPassword(), member.getPassword())) {
            throw new BadCredentialsException("비밀번호를 확인해주세요.");
        }

        return SignResponse.builder()
                .id(member.getId())
                .account(member.getAccount())
                .name(member.getName())
                .nickname(member.getNickname())
                .email(member.getEmail())
                .roles(member.getRoles())
                .token(TokenDto.builder()
                        .accessToken(jwtProvider.createAccessToken(member.getAccount(), member.getRoles()))
                        .refreshToken(member.getRefreshToken())
                        .build())
                .build();
    }

    public boolean register(SignRequest request) throws Exception {
        try {
            Member member = Member.builder()
                    .account(request.getAccount())
                    .password(passwordEncoder.encode(request.getPassword()))
                    .name(request.getName())
                    .nickname(request.getNickname())
                    .email(request.getEmail())
                    .build();
            member.setRoles(Collections.singletonList(Authority.builder().name("ROLE_USER").build()));

            memberRepository.save(member);
        } catch (Exception e) {
            System.out.println(e.getMessage());
            throw new Exception("잘못된 요청입니다.");
        }
        return true;
    }

    public SignResponse getMember(String account) throws Exception {
        Member member = memberRepository.findByAccount(account).orElseThrow(() -> new Exception("계정을 찾을 수 없습니다."));
        return new SignResponse(member);
    }

    // Refresh Token ---------

    public String createRefreshToken(Member member) {
        Token token = tokenRepository.save(
                Token.builder()
                        .id(member.getId())
                        .refreshToken(UUID.randomUUID().toString())
                        .expiration(120)
                        .build()
        );
        return token.getRefreshToken();
    }

    public Token validRefreshToken(Member member, String refreshToken) throws Exception {
        Token token = tokenRepository.findById(member.getId()).orElseThrow(() -> new Exception("만료된 계정입니다. 다시 로그인해주세요"));

        if (token.getRefreshToken() == null) {
            return null;
        } else {
            // 수정
            if (token.getExpiration() < 10) {
                //createRefreshToken(member);
                token.setExpiration(1000);
                tokenRepository.save(token);
            }

            if (!token.getRefreshToken().equals(refreshToken)) {
                return null;
            } else {
                return token;
            }
        }
    }

    public TokenDto refreshAccessToken(TokenDto tokenDto) throws Exception {
        String account = jwtProvider.getAccount(tokenDto.getAccessToken());
        Member member = memberRepository.findByAccount(account).orElseThrow(() -> new UsernameNotFoundException("잘못된 계정 정보입니다."));
        Token refreshTokenTemp = validRefreshToken(member, tokenDto.getRefreshToken());

        if (refreshTokenTemp != null) {
            return TokenDto.builder()
                    .accessToken(jwtProvider.createAccessToken(account, member.getRoles()))
                    .refreshToken(refreshTokenTemp.getRefreshToken())
                    .build();
        } else {
            throw new Exception("로그인을 해주세요.");
        }

    }
}

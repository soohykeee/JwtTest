package com.example.jwttest.security;

import com.example.jwttest.member.Member;
import com.example.jwttest.member.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
/*
 Spring Security의 UserDetailsService는 UserDetails 정보를 토대로 유저 정보를 불러올 때 사용
  + JPA를 활용하여 DB에 접근해서 유저 정보를 조회해서 CustomUserDetails에 넘겨준다.
 */
public class JpaUserDetailsService implements UserDetailsService {

    private final MemberRepository memberRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        Member member = memberRepository.findByAccount(username).orElseThrow(
                // DB에 유효하지 않은 유저로 로그인 시도 했을 경우 Exception
                () -> new UsernameNotFoundException("Invalid Authentication !")
        );

        return new CustomUserDetails(member);
    }

}

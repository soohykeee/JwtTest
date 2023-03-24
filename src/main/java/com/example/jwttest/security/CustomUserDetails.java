package com.example.jwttest.security;

import com.example.jwttest.member.Member;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.stream.Collectors;

/*
UserDetails 를 바로 Member에 상속해서 사용해도 동작은 하겠지만,
그렇게 하면 Member entity가 오염되어 향후 Member 엔티티를 사용하기 어려워지기에 CustomUserDetails 클래스를 생성하여
해당 클래스에 상속받아서 사용.

+  isAccountNonExpired, isAccountNonLocked, isCredentialsNonExpired, isEnabled -> JWT를 사용하기에 true 해주었다.
 */

public class CustomUserDetails implements UserDetails {

    private final Member member;

    public CustomUserDetails(Member member) {
        this.member = member;
    }

    public final Member getMember() {
        return member;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return member.getRoles().stream().map(
                o -> new SimpleGrantedAuthority(o.getName())
        ).collect(Collectors.toList());
    }

    @Override
    public String getPassword() {
        return member.getPassword();
    }

    @Override
    public String getUsername() {
        return member.getAccount();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}

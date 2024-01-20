package com.tarun.usermicroservice.security;

import com.tarun.usermicroservice.models.User;
import com.tarun.usermicroservice.repositories.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class SpringUserDetailsService implements UserDetailsService {

    private UserRepository userRepository;

    public SpringUserDetailsService(UserRepository userRepository){
        this.userRepository = userRepository;
    }
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<User> optionalUser = userRepository.findByEmail(username);
        if(optionalUser.isEmpty()){
            throw  new UsernameNotFoundException("User doesn't exist");
        }
        User user = optionalUser.get();
        return new CustomUserDetails(user);
    }
}

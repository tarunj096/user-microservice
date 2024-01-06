package com.tarun.usermicroservice.services;


import com.tarun.usermicroservice.dtos.UserDto;
import com.tarun.usermicroservice.models.Role;
import com.tarun.usermicroservice.models.Session;
import com.tarun.usermicroservice.models.SessionStatus;
import com.tarun.usermicroservice.models.User;
import com.tarun.usermicroservice.repositories.SessionRepository;
import com.tarun.usermicroservice.repositories.UserRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.MacAlgorithm;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.time.DateUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.MultiValueMapAdapter;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.*;

@Service
public class AuthService {
    private UserRepository userRepository;
    private SessionRepository sessionRepository;
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    public AuthService(UserRepository userRepository, SessionRepository sessionRepository, BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.userRepository = userRepository;
        this.sessionRepository = sessionRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    public ResponseEntity<UserDto> login(String email, String password) {
        Optional<User> userOptional = userRepository.findByEmail(email);

        if (userOptional.isEmpty()) {
            return null;
        }

        User user = userOptional.get();

        if (!bCryptPasswordEncoder.matches(password, user.getPassword())) {
            //throw an exception
            throw new RuntimeException("Wrong password entered");
        }
        //Generating a token
        //String token = RandomStringUtils.randomAlphanumeric(30);

        MacAlgorithm alg = Jwts.SIG.HS256; //or HS384 or HS256
        SecretKey key = alg.key().build();

//        String message = "Hello World!";
        Map<String,Object> jsonMap = new HashMap<>();
        jsonMap.put("email",user.getEmail());
        jsonMap.put("roles", List.of(user.getRoles()));
        jsonMap.put("createdAt",new Date());
        jsonMap.put("expiryAt", DateUtils.addDays(new Date(),30));
        //byte[] content = message.getBytes(StandardCharsets.UTF_8);

        // Create the compact JWS:
        String jws = Jwts.builder().claims(jsonMap).signWith(key,alg).compact();
        // Parse the compact JWS:
        //content = Jwts.parser().verifyWith(key).build().parseSignedContent(jws).getPayload();

        //assert message.equals(new String(content, StandardCharsets.UTF_8));

        Session session = new Session();
        session.setSessionStatus(SessionStatus.ACTIVE);
        session.setToken(jws);
        session.setUser(user);
        sessionRepository.save(session);

        UserDto userDto = new UserDto();
        userDto.setEmail(email);

        MultiValueMapAdapter<String, String> headers = new MultiValueMapAdapter<>(new HashMap<>());
        headers.add(HttpHeaders.SET_COOKIE, "auth-token:" + jws);

        ResponseEntity<UserDto> response = new ResponseEntity<>(userDto, headers, HttpStatus.OK);

        return response;
    }

    public ResponseEntity<Void> logout(String token, Long userId) {
        Optional<Session> sessionOptional = sessionRepository.findByTokenAndUser_Id(token, userId);

        if (sessionOptional.isEmpty()) {
            return null;
        }

        Session session = sessionOptional.get();

        session.setSessionStatus(SessionStatus.ENDED);

        sessionRepository.save(session);

        return ResponseEntity.ok().build();
    }

    public UserDto signUp(String email, String password) {
        User user = new User();
        user.setEmail(email);
        user.setPassword(bCryptPasswordEncoder.encode(password)); // We should store the encrypted password in the DB for a user.
        
        User savedUser = userRepository.save(user);

        return UserDto.from(savedUser);
    }

    public SessionStatus validate(String token, Long userId) {
        Optional<Session> sessionOptional = sessionRepository.findByTokenAndUser_Id(token, userId);

        if (sessionOptional.isEmpty()) {
            return null;
        }

        Session session = sessionOptional.get();
        if(session.getSessionStatus().equals(SessionStatus.ACTIVE)){
            return SessionStatus.ENDED;
        }
        Date currentTime = new Date();
        if (session.getExpiringAt().before(currentTime)){
            return SessionStatus.ENDED;
        }

        Jws<Claims> jwsclaims = Jwts.parser().build().parseSignedClaims(token);
        String email = (String) jwsclaims.getPayload().get("email");
        List<Role> jwsRoles = (List<Role>) jwsclaims.getPayload().get("roles");
        Date createdAt = (Date) jwsclaims.getPayload().get("createdat");

        return SessionStatus.ACTIVE;
    }

    //auth-token:eyJjdHkiOiJ0ZXh0L3BsYWluIiwiYWxnIjoiSFMyNTYifQ.SGVsbG8gV29ybGQh.z6Sw83W40CMfqZBvGv0cXstcWVIuRxVjRfUeHd9uWFY

}

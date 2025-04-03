package com.group3.BookOnTheGo.Authentication.Service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.group3.BookOnTheGo.Authentication.DataTransferObject.*;
import com.group3.BookOnTheGo.Email.Service.IEmailService;
import com.group3.BookOnTheGo.Enum.Role;
import com.group3.BookOnTheGo.Config.ApplicationConfig;
import com.group3.BookOnTheGo.Exception.MetaBlogException;
import com.group3.BookOnTheGo.Jwt.ServiceLayer.JwtService;
import com.group3.BookOnTheGo.OTP.Service.IOTPService;
import com.group3.BookOnTheGo.User.Model.User;
import com.group3.BookOnTheGo.User.Repository.IUserRepository;
import com.group3.BookOnTheGo.Utils.MetaBlogResponse;
import io.jsonwebtoken.io.Decoder;
import jakarta.mail.MessagingException;
import lombok.AllArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Service;

import org.apache.commons.codec.binary.Base64;

import java.util.Collection;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import static java.util.Base64.getUrlDecoder;

@Service
@AllArgsConstructor
public class AuthenticationService implements IAuthenticationService {
    private final IUserRepository IUserRepository;
    private final IOTPService otpService;
    private final IEmailService emailService;
    private final JwtService jwtService;
    private final Logger logger = LoggerFactory.getLogger(AuthenticationService.class);
    private final ApplicationConfig applicationConfig;
    private final AuthenticationManager authenticationManager;

    @Override
    public ResponseEntity<Object> register(RegisterRequestDto request) {
        try {
            logger.info("Registering user with email: {}", request.getEmail());
            Optional<User> existingUser = IUserRepository.findByEmail(request.getEmail());
            if (existingUser.isPresent()) {
                logger.error("User already exists with email: {}", request.getEmail());
                return new ResponseEntity<>(MetaBlogResponse.builder()
                        .success(false)
                        .message("User already exists with this email.")
                        .data(RegisterResponseDto.builder()
                                .accessToken(null)
                                .refreshToken(null)
                                .role(null)
                                .build())
                        .build(), HttpStatus.CONFLICT);
            }
        if (Objects.isNull(request.getRole()) || request.getRole().isEmpty()) {
                logger.error("Invalid Role provided in the request which is: {}", request.getRole());
            }

            var user = User.builder()
                    .username(request.getUsername())
                    .email(request.getEmail())
                    .password(applicationConfig.passwordEncoder().encode(request.getPassword()))
                    .registerAt((double) (System.currentTimeMillis()))
                    .lastLoginTime((double) (System.currentTimeMillis()))
                    .role(Role.valueOf(request.getRole()))
                    .isEmailVerified(false)
                    .isAccountLocked(false)
                    .isResetPasswordRequested(false)
                    .isTermsAccepted(true)
                    .build();

            IUserRepository.save(user);
            Long user_id = user.getId();

            int otp = otpService.generateOTP();
            otpService.registerOTP(otp, user_id);
            try {
                emailService.sendVerificationOTP(request.getEmail(), otp);
            } catch (MessagingException e) {
                logger.error("Error sending email to the user with email: {}", request.getEmail());
                logger.error("Message of the error: {}", e.getMessage());
                return new ResponseEntity<>(MetaBlogResponse.builder()
                        .success(false)
                        .message("Error sending email to the user.")
                        .build(), HttpStatus.INTERNAL_SERVER_ERROR);
            }
            logger.info("OTP sent to the user with email ");
            IUserRepository.save(user);
            logger.info("User created without JWT tokens");
            String accessToken = jwtService.generateJwtToken(user);
            String refreshToken = jwtService.generateRefreshToken(user);

            user.setRefreshToken(refreshToken);
            user.setAccessToken(accessToken);

            IUserRepository.save(user);

            logger.info("JWT token added to the user");
            logger.info("Registration ended successfully with email: {}", request.getEmail());
            return new ResponseEntity<>(MetaBlogResponse.builder()
                    .success(true)
                    .message("User Created Successfully")
                    .data(RegisterResponseDto.builder()
                            .accessToken(accessToken)
                            .refreshToken(refreshToken)
                            .role("Attendee")
                            .build())
                    .build(), HttpStatus.CREATED);
        } catch (MetaBlogException e) {
            return ResponseEntity.badRequest().body(MetaBlogResponse.builder()
                    .success(false)
                    .message(e.getMessage())
                    .build());
        }
    }

    @Override
    public ResponseEntity<Object> forgetPassword(String email) {
        try {
            logger.info("Forgot password request for email: {}", email);
            Optional<User> existingUser = IUserRepository.findByEmail(email);
            if (existingUser.isEmpty()) {
                logger.error("User does not exist with this email");
                return new ResponseEntity<>(MetaBlogResponse.builder()
                        .success(false)
                        .message("User does not exist with this email.")
                        .build(), HttpStatus.NOT_FOUND);
            }
            int otp = otpService.generateOTP();
            logger.info("OTP generated");
            User currentUser = existingUser.get();
            Long id = currentUser.getId();
            otpService.registerOTP(otp, id);
            try {
                emailService.sendVerificationOTP(email, otp);
            } catch (MessagingException e) {
                logger.error("Error sending email to the user with email: {}", email);
                logger.error("Message of the error: {}", e.getMessage());
                return new ResponseEntity<>(MetaBlogResponse.builder()
                        .success(false)
                        .message("Error sending email to the user.")
                        .build(), HttpStatus.INTERNAL_SERVER_ERROR);
            }
            logger.info("OTP sent to this email: {}", email);
            return new ResponseEntity<>(MetaBlogResponse.builder()
                    .success(true)
                    .message("OTP has been sent to your email successfully.")
                    .build(), HttpStatus.OK);
        } catch (MetaBlogException e) {
            return ResponseEntity.badRequest().body(MetaBlogResponse.builder()
                    .success(false)
                    .message(e.getMessage())
                    .build());
        }
    }

    @Override
    public ResponseEntity<Object> resetPassword(ResetPasswordRequestDto request) {
        try {
            logger.info("Resetting password for email: {}", request.getEmail());

            Optional<User> userOptional = IUserRepository.findByEmail(request.getEmail());
            if (userOptional.isEmpty()) {
                logger.error("User not found with email: {}", request.getEmail());
                return ResponseEntity.badRequest().body(MetaBlogResponse.builder()
                        .success(false)
                        .message("User not found.")
                        .build());
            }

            User user = userOptional.get();
            user.setPassword(applicationConfig.passwordEncoder().encode(request.getNewPassword()));
            IUserRepository.save(user);
            logger.info("Password reset successfully");

            return ResponseEntity.ok().body(MetaBlogResponse.builder()
                    .success(true)
                    .message("Password reset successfully.")
                    .build());
        } catch (MetaBlogException e) {
            return ResponseEntity.badRequest().body(MetaBlogResponse.builder()
                    .success(false)
                    .message(e.getMessage())
                    .build());
        }
    }

    @Override
    public ResponseEntity<Object> findUser(String email) {
        try {
            logger.info("Finding user with email: {}", email);
            Optional<User> existingUser = IUserRepository.findByEmail(email);
            if (existingUser.isEmpty()) {
                logger.error("User does not exist with this email");
                return new ResponseEntity<>(MetaBlogResponse.builder()
                        .success(false)
                        .message("User does not exist with this email.")
                        .build(), HttpStatus.NOT_FOUND);
            }
            logger.info("User found with this email");
            return new ResponseEntity<>(MetaBlogResponse.builder()
                    .success(true)
                    .message("A user with this email exists.")
                    .build(), HttpStatus.OK);
        } catch (MetaBlogException e) {
            return ResponseEntity.badRequest().body(MetaBlogResponse.builder()
                    .success(false)
                    .message(e.getMessage())
                    .build());
        }
    }

    @Override
    public ResponseEntity<Object> login(LoginRequestDto request) {
        try {
            User user = IUserRepository.findByEmail(request.getEmail())
                    .orElseThrow(() -> new MetaBlogException("User not found"));

            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));

            String accessToken = jwtService.generateJwtToken(user);
            String refreshToken = jwtService.generateRefreshToken(user);

            user.setLastLoginTime((double) System.currentTimeMillis());
            user.setAccessToken(accessToken);
            user.setRefreshToken(refreshToken);
            IUserRepository.save(user);

            return new ResponseEntity<>(MetaBlogResponse.builder()
                    .success(true)
                    .message("Login successful")
                    .data(LoginResponseDto.builder()
                            .accessToken(accessToken)
                            .refreshToken(refreshToken)
                            .role(user.getRole().name())
                            .build())
                    .build(), HttpStatus.OK);
        } catch (MetaBlogException e) {
            return ResponseEntity.badRequest().body(MetaBlogResponse.builder()
                    .success(false)
                    .message(e.getMessage())
                    .build());
        }
    }
}

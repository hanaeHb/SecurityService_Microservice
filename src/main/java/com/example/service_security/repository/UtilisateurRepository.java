package com.example.service_security.repository;

import com.example.service_security.entity.user;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UtilisateurRepository extends JpaRepository<user, Integer>{
    Optional<user> findByUsername(String username);
}

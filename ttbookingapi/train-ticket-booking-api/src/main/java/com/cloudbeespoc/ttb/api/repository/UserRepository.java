package com.cloudbeespoc.ttb.api.repository;

import com.cloudbeespoc.ttb.api.bean.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    User findByEmail(String email);

    // Corrected method: retrieve users by preferred section
    List<User> findAllByPreferredSection(String section);

    // Corrected method: retrieve user by seat number
    User findBySeatNumber(String seatNumber);

    User findByFirstNameOrLastName(String firstName, String lastName);


}

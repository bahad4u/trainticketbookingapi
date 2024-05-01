package com.cloudbeespoc.ttb.api.service;

import com.cloudbeespoc.ttb.api.bean.User;

import java.util.List;

public interface UserService {

    User getUserById(Long id);

    User getUserByEmail(String email);

    void saveUser(User user);

    void deleteUser(User user);

    List<User> getUsersBySection(String section);

    User getUserBySeatNumber(String seatNumber);

    User getUserByFirstNameOrLastName(String firstName, String lastName);
}

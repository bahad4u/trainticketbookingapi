package com.cloudbeespoc.ttb.api.service;

import com.cloudbeespoc.ttb.api.exception.UserNotFoundException;
import com.cloudbeespoc.ttb.api.bean.User;
import com.cloudbeespoc.ttb.api.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserServiceImpl implements UserService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public User getUserById(Long id) {
        return userRepository.findById(id).orElseThrow(() -> new UserNotFoundException("User not found with ID: " + id));
    }

    @Override
    public User getUserByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    @Override
    public void saveUser(User user) {
        userRepository.save(user);
    }

    @Override
    public void deleteUser(User user) {
        userRepository.deleteById(user.getId());
    }

    @Override
    public List<User> getUsersBySection(String section) {
        return userRepository.findAllByPreferredSection(section);
    }

    @Override
    public User getUserBySeatNumber(String seatNumber) {
        return userRepository.findBySeatNumber(seatNumber);
    }

    @Override
    public User getUserByFirstNameOrLastName(String firstName, String lastName) {
        return userRepository.findByFirstNameOrLastName(firstName, lastName);
    }

}

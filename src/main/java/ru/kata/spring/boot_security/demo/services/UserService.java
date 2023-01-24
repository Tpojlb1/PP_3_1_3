package ru.kata.spring.boot_security.demo.services;

import org.springframework.stereotype.Service;
import ru.kata.spring.boot_security.demo.models.Role;
import ru.kata.spring.boot_security.demo.models.User;

import java.util.List;

    @Service
    public interface UserService {
    List<User> getAllUsers();

    void create(User user);

    void delete(long id);

    void update(User user);

    User getById(long id);
}

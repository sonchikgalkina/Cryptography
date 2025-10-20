package org.example.cryptography.service;

import org.example.cryptography.model.Room;
import org.example.cryptography.model.User;
import org.example.cryptography.repository.UserRepository;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UserService {
    private final UserRepository userRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public Optional<User> getUserById(long id) {
        return userRepository.findById(id);
    }

    public void addRoomToUser(User user, Room room) {
        user.getRooms().add(room);
        userRepository.save(user);
    }

    public boolean removeRoomFromUser(User user, Room room) {
        if (user.getRooms().contains(room)) {
            user.getRooms().remove(room);
            userRepository.save(user);
            return true;
        }
        return false;
    }
}

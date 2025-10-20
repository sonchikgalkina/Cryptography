package org.example.cryptography.repository;

import org.example.cryptography.model.Room;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface RoomRepository extends JpaRepository<Room, Long> {
    Optional<Room> findByName(String roomName);

    List<Room> findAllByUsersId(Long userId);

    boolean existsByName(String roomName);
}

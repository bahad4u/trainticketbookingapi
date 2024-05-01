package com.cloudbeespoc.ttb.api.repository;

import com.cloudbeespoc.ttb.api.bean.Seat;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface SeatRepository extends JpaRepository<Seat, String> {

    Seat findTopBySectionAndSeatAvailable(String section, boolean seatAvailable);

    Seat findBySeatNumber (String seatNumber);
}

package com.cloudbeespoc.ttb.api.service;

import com.cloudbeespoc.ttb.api.exception.SeatNotFoundException;
import com.cloudbeespoc.ttb.api.bean.Seat;
import com.cloudbeespoc.ttb.api.bean.Train;
import com.cloudbeespoc.ttb.api.repository.SeatRepository;
import com.cloudbeespoc.ttb.api.repository.TrainRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Service
public class SeatAllocationServiceImpl implements SeatAllocationService {

    @Autowired
    private SeatRepository seatRepository;

    @Autowired
    private TrainRepository trainRepository;

    @Override
    public void initializeSeats() {
        Train train = new Train();
        train.setTrainName("LP01");
        trainRepository.save(train);
        List<Seat> seatList = new ArrayList<>();
        List<String> sections = Arrays.asList("A", "B");
        for (String section : sections) {
            for (int i = 1; i <= 10; i++) {
                Seat seat = new Seat();
                seat.setSeatNumber(section + i);
                seat.setSection(section);
                seat.setSeatAvailable(true);
                seat.setFare(5.0);
                seat.setTrain(train);
                seatRepository.save(seat);
            }

        }
    }

    @Override
    public Seat allocateSeat(String value) {
        Seat availableSeat = seatRepository.findTopBySectionAndSeatAvailable(value, true);
        if (availableSeat != null) {
            availableSeat.setSeatAvailable(false);
            seatRepository.save(availableSeat);
            return availableSeat;
        }
        throw new SeatNotFoundException("No seats available in section: ");
    }

    @Override
    public void releaseSeat(String seatNumber) {
        Seat seat = seatRepository.findBySeatNumber(seatNumber);
        if (seat == null) {
            throw new SeatNotFoundException("Seat not found for the seat Number: " + seatNumber);
        }
        seat.setSeatAvailable(true);
        seatRepository.save(seat);
    }
}

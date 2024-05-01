package com.cloudbeespoc.ttb.api.service;

import com.cloudbeespoc.ttb.api.bean.Seat;

public interface SeatAllocationService {
    void initializeSeats();

    Seat allocateSeat(String value);

    void releaseSeat(String seatNumber);
}

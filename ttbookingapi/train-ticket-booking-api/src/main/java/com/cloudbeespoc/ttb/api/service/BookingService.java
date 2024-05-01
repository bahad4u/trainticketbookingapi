package com.cloudbeespoc.ttb.api.service;

import com.cloudbeespoc.ttb.api.exception.SeatNotFoundException;
import com.cloudbeespoc.ttb.api.exception.UserNotFoundException;
import com.cloudbeespoc.ttb.api.bean.Ticket;
import com.cloudbeespoc.ttb.api.bean.User;
import com.cloudbeespoc.ttb.api.request.TicketRequest;

import java.util.List;

public interface BookingService {
    List<Ticket> purchaseTicket(TicketRequest ticketRequest);

    Ticket getTicketByUserName(Long ticketId) throws UserNotFoundException;

    List<User> getUsersBySection(String section);

    void removeUser(String seatNumber) throws UserNotFoundException;

    void modifyUserSeat(String seatNumber, String newSection) throws UserNotFoundException, SeatNotFoundException;
}

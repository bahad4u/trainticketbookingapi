package com.cloudbeespoc.ttb.api.service;

import com.cloudbeespoc.ttb.api.bean.Seat;
import com.cloudbeespoc.ttb.api.exception.SeatNotFoundException;
import com.cloudbeespoc.ttb.api.exception.UserNotFoundException;
import com.cloudbeespoc.ttb.api.bean.Ticket;
import com.cloudbeespoc.ttb.api.bean.User;
import com.cloudbeespoc.ttb.api.repository.TicketRepository;
import com.cloudbeespoc.ttb.api.request.TicketRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.util.*;

@Service
public class BookingServiceImpl implements BookingService {

    @Autowired
    private UserService userService;

    @Autowired
    private SeatAllocationService seatAllocationService;

    @Autowired
    private TicketRepository ticketRepository;

    @Override
    @Transactional
    public List<Ticket> purchaseTicket(TicketRequest ticketRequest) {
        List<Ticket> tickets = new ArrayList<>();

        for (User user : ticketRequest.getUsers()) {
            Seat seat = seatAllocationService.allocateSeat(user.getPreferredSection());
            user.setSeatNumber(seat.getSeatNumber());
            user.setFrom(ticketRequest.getFrom());
            user.setTo(ticketRequest.getTo());
            user.setAmountPaid(seat.getFare());
            userService.saveUser(user);
            Ticket ticket = new Ticket();
            ticket.setFrom(ticketRequest.getFrom());
            ticket.setTo(ticketRequest.getTo());
            ticket.setUser(user);
            ticket.setPrice(seat.getFare());
            ticketRepository.save(ticket);
            tickets.add(ticket);
        }

        return tickets;
    }

    @Override
    public Ticket getTicketByUserName(Long ticketId) throws UserNotFoundException {

        return ticketRepository.findById(ticketId).orElseThrow(() -> new UserNotFoundException("Receipt not found for ticketId: " + ticketId));
    }

    @Override
    @Transactional
    public List<User> getUsersBySection(String section) {
        return userService.getUsersBySection(section);
    }

    @Override
    @Transactional
    public void removeUser(String seatNumber) throws UserNotFoundException {
        User user = userService.getUserBySeatNumber(seatNumber);
        ticketRepository.deleteTicketByUser(user);
        seatAllocationService.releaseSeat(seatNumber);
        userService.deleteUser(user);
    }

    @Override
    @Transactional
    public void modifyUserSeat(String seatNumber, String newSection) throws UserNotFoundException, SeatNotFoundException {
        User user = userService.getUserBySeatNumber(seatNumber);
        seatAllocationService.releaseSeat(seatNumber);
        Seat newSeatNumber = seatAllocationService.allocateSeat(newSection);
        user.setSeatNumber(newSeatNumber.getSeatNumber());
        userService.saveUser(user);
    }
}

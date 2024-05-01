package com.cloudbeespoc.ttb.api.controller;

import com.cloudbeespoc.ttb.api.exception.SeatNotFoundException;
import com.cloudbeespoc.ttb.api.exception.UserNotFoundException;
import com.cloudbeespoc.ttb.api.bean.Ticket;
import com.cloudbeespoc.ttb.api.bean.User;
import com.cloudbeespoc.ttb.api.request.TicketRequest;
import com.cloudbeespoc.ttb.api.service.BookingService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Required;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@Tag(name = "Train Ticket Booking API")
public class BookingController {

    @Autowired
    private BookingService bookingService;

    @Operation(method = "POST", summary = "To Purchase train ticket ")
    @ApiResponse(responseCode = "200", description = "Success")
    @ApiResponse(responseCode = "400", description = "Submitted request is inValid")
    @PostMapping("/purchaseTicket")
    public ResponseEntity<Map<String, String>> purchaseTicket(@RequestBody TicketRequest ticketRequest) {
        List<Ticket> tickets = bookingService.purchaseTicket(ticketRequest);
        Map<String, String> response = new HashMap<>();
        for (Ticket ticket : tickets) {
            response.put(ticket.getUser().getFirstName() + " " + ticket.getUser().getLastName(), "Ticket booked successfully with ticket Id " + ticket.getId().toString());
        }

        return new ResponseEntity<>(response, HttpStatus.CREATED);
    }

    @Operation(method = "GET", summary = "Download the ticket receipt using ticketId")
    @ApiResponse(responseCode = "200", description = "Success")
    @ApiResponse(responseCode = "400", description = "Submitted request is inValid")
    @GetMapping("/receipt")
    public ResponseEntity<Resource> getReceipt(@Parameter(required = true) Long ticketId) throws UserNotFoundException {
        Ticket ticket = bookingService.getTicketByUserName(ticketId);

        StringBuilder receiptContent = new StringBuilder();
        receiptContent.append("Ticket Details:\n");
        receiptContent.append("From: ").append(ticket.getFrom()).append("\n");
        receiptContent.append("To: ").append(ticket.getTo()).append("\n");
        receiptContent.append("User:\n");
        receiptContent.append("  - Name: ").append(ticket.getUser().getFirstName()).append(" ").append(ticket.getUser().getLastName()).append("\n");
        receiptContent.append("  - Seat Number: ").append(ticket.getUser().getSeatNumber()).append("\n");
        receiptContent.append("Price: $").append(ticket.getPrice()).append("\n");

        byte[] receiptData = receiptContent.toString().getBytes(StandardCharsets.UTF_8);

        String fileName = "receipt_" + ticket.getId() + ".txt";

        Resource resource = new ByteArrayResource(receiptData);

        return ResponseEntity.ok()
                .contentType(MediaType.TEXT_PLAIN)
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + fileName + "\"")
                .body(resource);
    }

    @Operation(method = "Get", summary = "Get User information using section")
    @ApiResponse(responseCode = "200", description = "Success")
    @ApiResponse(responseCode = "400", description = "Submitted request is inValid")
    @GetMapping("/users/{section}")
    public ResponseEntity<String> getUsersBySection(@PathVariable String section) {
        return new ResponseEntity<>(bookingService.getUsersBySection(section).toString(), HttpStatus.OK);
    }

    @Operation(method = "Delete", summary = "Remove user with seatNumber")
    @ApiResponse(responseCode = "200", description = "Success")
    @ApiResponse(responseCode = "400", description = "Submitted request is inValid")
    @DeleteMapping("/user/{seatNumber}")
    public ResponseEntity<Void> removeUser(@PathVariable String seatNumber) throws UserNotFoundException {
        bookingService.removeUser(seatNumber);
        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }

    @Operation(method = "PUT", summary = "Modify User seat with new section")
    @ApiResponse(responseCode = "200", description = "Success")
    @ApiResponse(responseCode = "400", description = "Submitted request is inValid")
    @PutMapping("/user/{seatNumber}/{newSection}")
    public ResponseEntity<Void> modifyUserSeat(@PathVariable String seatNumber, @PathVariable String newSection) throws UserNotFoundException, SeatNotFoundException {
        bookingService.modifyUserSeat(seatNumber, newSection);
        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }
}
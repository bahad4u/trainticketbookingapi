package com.cloudbeespoc.ttb.api.controller;

import com.cloudbeespoc.ttb.api.JsonUtils;
import com.cloudbeespoc.ttb.api.bean.Ticket;
import com.cloudbeespoc.ttb.api.bean.User;
import com.cloudbeespoc.ttb.api.exception.UserNotFoundException;
import com.cloudbeespoc.ttb.api.service.BookingService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.util.NestedServletException;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@RunWith(SpringRunner.class)
@SpringBootTest
@WebAppConfiguration
public class BookingControllerTest {

    @Autowired
    private WebApplicationContext wac;
    private MockMvc mockMvc;

    @MockBean
    private BookingService bookingService;

    @Autowired
    private ObjectMapper objectMapper;

    @Before
    public void setUp(){
        mockMvc = MockMvcBuilders.webAppContextSetup(wac).build();
    }

    @Test
    public void purchaseTicketTest() throws Exception {
        MvcResult requestResult =  mockMvc.perform(post("/purchaseTicket")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"users\":[{\"firstName\":\"AB\",\"lastName\":\"\"," +
                                "\"email\":\"ab@gmai.com\",\"preferredSection\":\"A\"}]," +
                                "\"from\":\"London\",\"train_id\":1,\"to\":\"Paris\"}"))
                    .andExpect(status().isCreated()).andReturn();

        Map<String, String> response = new ObjectMapper().readValue(requestResult.getResponse().getContentAsString(), Map.class);


        Assert.assertTrue(response.get("AB ").equals("Ticket booked successfully with ticket Id 23"));

    }

    @Test
    public void testGetReceiptSuccess() throws Exception {
        Long existingTicketId = 1L; // Replace with an existing ticket ID

        Ticket mockTicket = new Ticket();
        mockTicket.setId(existingTicketId);
        mockTicket.setFrom("Chennai");
        mockTicket.setTo("Bangalore");
        User user = new User();
        user.setFirstName("John");
        user.setLastName("Doe");
        user.setSeatNumber("A1");
        mockTicket.setUser(user);
        mockTicket.setPrice(10.0);

        when(bookingService.getTicketByUserName(existingTicketId)).thenReturn(mockTicket);

        mockMvc.perform(get("/receipt?ticketId=" + existingTicketId))
                .andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"receipt_" + existingTicketId + ".txt\""))
                .andExpect(content().contentType(MediaType.TEXT_PLAIN));
    }

    @Test
    public void testGetReceiptInvalidId() throws Exception {
        Long invalidTicketId = 99L;

        when(bookingService.getTicketByUserName(invalidTicketId)).thenThrow(new UserNotFoundException("Ticket not found"));

        try {
            MvcResult requestResult = mockMvc.perform(get("/receipt?ticketId=" + invalidTicketId)).andReturn();
        }catch (Exception e){
           assertEquals(e.getCause().getMessage(), "Ticket not found");
        }

    }

    @Test
    public void testGetUsersBySectionSuccess() throws Exception {
        String existingSection = "A";

        List<User> mockUsers = new ArrayList<>();
        User user = new User();
        user.setFirstName("John");
        user.setLastName("Doe");
        user.setSeatNumber("A1");
        user.setPreferredSection("A");
        mockUsers.add(user);

        when(bookingService.getUsersBySection(existingSection)).thenReturn(mockUsers);

        mockMvc.perform(get("/users/" + existingSection))
                .andExpect(status().isOk());
    }

    @Test
    public void testGetUsersBySectionEmptyList() throws Exception {
        String emptySection = "EmptySection";

        when(bookingService.getUsersBySection(emptySection)).thenReturn(Collections.emptyList());

        mockMvc.perform(get("/users/" + emptySection))
                .andExpect(status().isOk())
                .andExpect(content().json("[]"));
    }

    @Test
    public void testRemoveUserSuccess() throws Exception {
        String existingSeatNumber = "A1"; // Replace with an existing seat number

        mockMvc.perform(delete("/user/" + existingSeatNumber))
                .andExpect(status().isNoContent());
    }

    @Test
    public void testModifyUserSeatSuccess() throws Exception {
        String existingSeatNumber = "A1";
        String newSection = "Business";

        mockMvc.perform(put("/user/" + existingSeatNumber + "/" + newSection))
                .andExpect(status().isNoContent());
    }
}

package com.cloudbeespoc.ttb.api.config;

import com.cloudbeespoc.ttb.api.service.SeatAllocationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;

import javax.annotation.PostConstruct;

@Configuration
public class AppConfig {

    @Autowired
    private SeatAllocationService seatAllocationService;

    @PostConstruct
    public void initializeSeats() {
        seatAllocationService.initializeSeats();
    }
}

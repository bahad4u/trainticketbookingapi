package com.cloudbeespoc.ttb.api.bean;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;

@Entity
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class Seat {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;
    private String seatNumber;
    private String section;
    private boolean seatAvailable;
    private double fare;
    @ManyToOne
    private Train train;
}

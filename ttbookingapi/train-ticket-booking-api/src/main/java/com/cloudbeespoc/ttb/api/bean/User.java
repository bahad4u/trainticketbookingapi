package com.cloudbeespoc.ttb.api.bean;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import javax.persistence.*;


@Getter
@Setter
@ToString(onlyExplicitlyIncluded = true)
@AllArgsConstructor
@Entity
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @JsonIgnore
    private Long id;
    @ToString.Include
    private String firstName;
    @ToString.Include
    private String lastName;
    @ToString.Include
    private String email;
    @JsonIgnore
    @ToString.Include
    private String seatNumber;
    private String preferredSection;
    @JsonIgnore
    @ToString.Include
    private String From;
    @JsonIgnore
    @ToString.Include
    private String To;
    @JsonIgnore
    private double amountPaid;

    public User() {

    }
}
package com.cloudbeespoc.ttb.api.bean;

import lombok.*;

import javax.persistence.*;

@Entity
@AllArgsConstructor
@Getter
@Setter
@ToString
public class Ticket {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;
    private String from;
    private String to;
    @ManyToOne(cascade = CascadeType.DETACH)
    private User user;
    private double price;

    public Ticket() {

    }
}

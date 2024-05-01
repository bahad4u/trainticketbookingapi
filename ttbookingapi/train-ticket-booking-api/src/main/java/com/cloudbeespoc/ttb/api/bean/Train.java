package com.cloudbeespoc.ttb.api.bean;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import javax.persistence.*;
import java.util.List;

@Entity
@Getter
@Setter
@AllArgsConstructor
public class Train {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;
    private String trainName;

    @OneToMany(mappedBy = "train")
    private List<Seat> seats;
    public Train() {

    }
}

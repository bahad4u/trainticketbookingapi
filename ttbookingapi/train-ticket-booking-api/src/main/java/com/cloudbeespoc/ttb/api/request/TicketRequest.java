package com.cloudbeespoc.ttb.api.request;

import com.cloudbeespoc.ttb.api.bean.User;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class TicketRequest {

    List<User> users;
    String from;
    String To;
    Long train_id;

}

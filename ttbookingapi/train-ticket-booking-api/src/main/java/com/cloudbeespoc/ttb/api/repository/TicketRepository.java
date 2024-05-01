package com.cloudbeespoc.ttb.api.repository;

import com.cloudbeespoc.ttb.api.bean.Ticket;
import com.cloudbeespoc.ttb.api.bean.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface TicketRepository extends JpaRepository<Ticket, Long> {
    Ticket findByUser(User user);

    void deleteTicketByUser(User user);

}

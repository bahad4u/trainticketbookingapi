package com.cloudbeespoc.ttb.api.repository;

import com.cloudbeespoc.ttb.api.bean.Train;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface TrainRepository extends JpaRepository<Train, Long> {


}

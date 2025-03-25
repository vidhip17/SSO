package sso.vidhi.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import sso.vidhi.entity.User;

@Repository
public interface UserRepo extends JpaRepository<User, Long> {
}

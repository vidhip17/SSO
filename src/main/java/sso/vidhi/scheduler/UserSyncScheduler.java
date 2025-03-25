package sso.vidhi.scheduler;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import sso.vidhi.service.LdapUserService;

@Component
public class UserSyncScheduler {

    @Autowired
    private LdapUserService ldapUserService;

    // Run the sync task every hour
    @Scheduled(fixedRate = 900000)
    public void syncUsers() {
        ldapUserService.syncUsersToLdap();
    }
}

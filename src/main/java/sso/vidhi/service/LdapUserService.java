package sso.vidhi.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.ldap.NameAlreadyBoundException;
import org.springframework.ldap.NameNotFoundException;
import org.springframework.ldap.NamingException;
import org.springframework.ldap.core.AttributesMapper;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.query.LdapQueryBuilder;
import org.springframework.ldap.support.LdapNameBuilder;
import org.springframework.ldap.support.LdapUtils;
import org.springframework.stereotype.Service;
import sso.vidhi.entity.User;
import sso.vidhi.repository.UserRepo;

import javax.naming.Name;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.SearchControls;
import java.util.Base64;
import java.util.List;

@Service
public class LdapUserService {

    String searchFilter = "(uid={0})";
    String baseDn = "ou=users";

//    @Autowired
//    private LdapTemplate ldapTemplate;

    private final LdapTemplate ldapTemplate;

    @Autowired
    public LdapUserService(LdapTemplate ldapTemplate) {
        this.ldapTemplate = ldapTemplate;
    }

    @Autowired
    private UserRepo userRepo;

    public void syncUsersToLdap() {

//        createOuIfNotExists("users");

        List<User> users = userRepo.findAll(); // Get all users from the DB

        for (User user : users) {
            // Check if user already exists in LDAP before adding
//            if (!isUserInLdap(user)) {
                addUserToLdap(user);
//            }
        }
    }

//    private boolean isUserInLdap(User user) {
//        return ldapTemplate.search(
//                "ou=users",
//                "(uid=" + user.getUserName() + ")",
//                (attributes) -> attributes.size() > 0
//        ).size() > 0;
//    }

    private void createOuIfNotExists(String ouName) {
        try {
            // Create the OU DN
            Name ouDn = LdapNameBuilder.newInstance(baseDn)
                    .add("ou", ouName)
                    .build();

            try {
                // Check if the OU already exists
                ldapTemplate.lookup(ouDn);

            } catch (org.springframework.ldap.NameNotFoundException e) {
                // OU does not exist, create it

                // Define OU attributes
                Attributes ouAttrs = new BasicAttributes();
                ouAttrs.put("objectClass", "top");
                ouAttrs.put("objectClass", "organizationalUnit");
                ouAttrs.put("ou", ouName);

                // Create the OU in LDAP
                ldapTemplate.bind(ouDn, null, ouAttrs);

            }
        } catch (NamingException e) {
            e.printStackTrace();
        }
    }




    private String escapeForLdapFilter(String input) {
        if (input == null) {
            return null;
        }

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            switch (c) {
                case '\\':
                    sb.append("\\5c");
                    break;
                case '*':
                    sb.append("\\2a");
                    break;
                case '(':
                    sb.append("\\28");
                    break;
                case ')':
                    sb.append("\\29");
                    break;
                case '\0':
                    sb.append("\\00");
                    break;
                default:
                    sb.append(c);
            }
        }
        return sb.toString();
    }

//    private void addUserToLdap(User user) {
//        Name dn = LdapNameBuilder.newInstance()
//                .add("ou", "users") // Define the Organizational Unit (OU)
//                .add("uid", user.getUserName()) // Set the UID (Username) for LDAP
//                .build();
//
//        Attributes attributes = new BasicAttributes();
//        attributes.put(new BasicAttribute("objectClass", "inetOrgPerson"));
//        attributes.put(new BasicAttribute("uid", user.getUserName()));
//        attributes.put(new BasicAttribute("cn", user.getUserName()));
//        attributes.put(new BasicAttribute("sn", user.getUserName()));
//        attributes.put(new BasicAttribute("mail", user.getEmail()));
//        attributes.put(new BasicAttribute("userPassword", user.getPassword())); // Ensure password is hashed
//
//        ldapTemplate.bind(dn, null, attributes);
//    }

//    private void addUserToLdap(User user) {
//        // Build the complete DN including the base DN
//        Name dn = LdapNameBuilder.newInstance()
//                .add("dc", "example")  // Base DN components
//                .add("dc", "org")      // Base DN components
//                .add("ou", "users")    // Organizational Unit
//                .add("uid", user.getUserName()) // User ID
//                .build();
//
//        Attributes attributes = new BasicAttributes();
//        attributes.put(new BasicAttribute("objectClass", "inetOrgPerson"));
//        attributes.put(new BasicAttribute("uid", user.getUserName()));
//        attributes.put(new BasicAttribute("cn", user.getUserName()));
//        attributes.put(new BasicAttribute("sn", user.getUserName()));
//        attributes.put(new BasicAttribute("mail", user.getEmail()));
//        attributes.put(new BasicAttribute("userPassword", user.getPassword())); // Ensure password is hashed
//
//        ldapTemplate.bind(dn, null, attributes);
//    }

//    private void addUserToLdap(User user) {
//        Name dn = LdapNameBuilder.newInstance()
//                .add("dc", "example")
//                .add("dc", "org")
//                .add("ou", "users")
//                .add("uid", user.getUserName())
//                .build();
//
//        Attributes attributes = new BasicAttributes();
//        attributes.put(new BasicAttribute("objectClass", "inetOrgPerson"));
//        attributes.put(new BasicAttribute("uid", user.getUserName()));
//        attributes.put(new BasicAttribute("cn", user.getUserName()));
//        attributes.put(new BasicAttribute("sn", user.getUserName()));
//        attributes.put(new BasicAttribute("mail", user.getEmail()));
//        attributes.put(new BasicAttribute("userPassword", user.getPassword())); // Hash this if needed
//
//        ldapTemplate.bind(dn, null, attributes);
//        System.out.println("Added user to LDAP: " + user.getUserName());
//    }

//    private void addUserToLdap(User user) {
//        // Build the DN (Distinguished Name) for the user
//        Name dn = LdapNameBuilder.newInstance()
//                .add("dc", "example")
//                .add("dc", "org")
//                .add("ou", "users")
//                .add("uid", user.getUserName()) // Unique identifier
//                .build();
//
//        // Check if the user already exists in LDAP
//        if (isUserInLdap(user)) {
//            System.out.println("User already exists in LDAP: " + user.getUserName());
//            // Optionally, update the user if needed, otherwise, skip the creation
//            return; // Skip adding the user if they exist
//        }
//
//        // Create attributes for the new user
//        Attributes attributes = new BasicAttributes();
//        attributes.put(new BasicAttribute("objectClass", "inetOrgPerson"));
//        attributes.put(new BasicAttribute("uid", user.getUserName()));
//        attributes.put(new BasicAttribute("cn", user.getUserName()));
//        attributes.put(new BasicAttribute("sn", user.getUserName()));
//        attributes.put(new BasicAttribute("mail", user.getEmail()));
//        attributes.put(new BasicAttribute("userPassword", user.getPassword())); // Hash this if needed
//
//        try {
//            // Add the user to LDAP
//            ldapTemplate.bind(dn, null, attributes);
//            System.out.println("Added user to LDAP: " + user.getUserName());
//        } catch (NameAlreadyBoundException e) {
//            // This exception is thrown when the DN already exists
//            System.out.println("User already exists in LDAP: " + user.getUserName());
//        } catch (Exception e) {
//            // Handle other exceptions (LDAP or network issues)
//            e.printStackTrace();
//        }
//    }

//    public void addUserToLdap(User user) {
//        // Correct DN format for user entry
//        Name dn = LdapNameBuilder.newInstance()
//                .add("uid", user.getUserName())  // Add the user's UID
//                .add("ou", "users")             // The organizational unit where users are stored
//                .add("dc", "example")           // Domain component for the example domain
//                .add("dc", "org")               // Domain component for the org domain
//                .build();
//
//        // Define the user's attributes
//        Attributes attributes = new BasicAttributes();
//        attributes.put(new BasicAttribute("objectClass", "inetOrgPerson"));
//        attributes.put(new BasicAttribute("uid", user.getUserName()));
//        attributes.put(new BasicAttribute("cn", user.getUserName()));
//        attributes.put(new BasicAttribute("sn", user.getUserName()));  // Assuming the user has a last name
//        attributes.put(new BasicAttribute("mail", user.getEmail()));
//        attributes.put(new BasicAttribute("userPassword", user.getPassword())); // Ensure this is hashed if required
//
//        try {
//            // Bind the user to LDAP (create the user)
//            ldapTemplate.bind(dn, null, attributes);
//            System.out.println("User added to LDAP: " + user.getUserName());
//        } catch (Exception e) {
//            System.out.println("Error adding user to LDAP: " + e.getMessage());
//            e.printStackTrace();
//        }
//    }

//    public void addUserToLdap(User user) {
//        try {
//            // Create the base DN
//            Name dn = LdapNameBuilder.newInstance(baseDn)
//                    .add("ou", "users")
//                    .add("uid", user.getUserName()) // User's unique identifier (username)
//                    .build();
//
//            // Define user attributes
//            Attributes attributes = new BasicAttributes();
//            attributes.put("objectClass", "top");
//            attributes.put("objectClass", "inetOrgPerson");
//            attributes.put("objectClass", "organizationalPerson"); // Organizational user
//            //attributes.put("uid", user.getUserName());
//            attributes.put("cn", user.getUserName()); // Common name
//            attributes.put("sn", user.getUserName()); // Surname
//            //attributes.put("mail", user.getEmail()); // Email address
//            attributes.put("userPassword", user.getPassword()); // User password (ensure it's hashed)
//
//            ldapTemplate.bind(dn, null, attributes);
//            System.out.println("Successfully added user to LDAP: " + user.getUserName());
//        } catch (Exception e) {
//            System.out.println("Error adding user to LDAP: " + e.getMessage());
//            e.printStackTrace();
//        }
//    }

//    public void addUserToLdap(User user) {
//        try {
//            // Create the base DN, including the organizational unit (ou) and user UID
//            Name dn = LdapNameBuilder.newInstance("ou=users,dc=example,dc=com") // Full base DN
//                    .add("uid", user.getUserName()) // Unique identifier (username)
//                    .build();
//
//            // Define user attributes
//            Attributes attributes = new BasicAttributes();
//            attributes.put("objectClass", "top");
//            attributes.put("objectClass", "inetOrgPerson"); // Standard user object class
//            attributes.put("objectClass", "organizationalPerson"); // More specific user class for organization
//
//            // Ensure 'uid' is included if needed by schema (uncomment if required)
//            attributes.put("uid", user.getUserName()); // User's unique identifier (username)
//            attributes.put("cn", user.getUserName()); // Common name
//            attributes.put("sn", user.getUserName()); // Surname
////            attributes.put("mail", user.getEmail()); // Email address (uncomment if your schema supports it)
//
//            // Assuming password needs to be hashed. Make sure to hash it appropriately if required.
//            attributes.put("userPassword", user.getPassword()); // User password (ensure it's hashed)
//
//            // Bind the user to LDAP
//            ldapTemplate.bind(dn, null, attributes);
//            System.out.println("Successfully added user to LDAP: " + user.getUserName());
//        } catch (Exception e) {
//            System.out.println("Error adding user to LDAP: " + e.getMessage());
//            e.printStackTrace();
//        }
//    }

//    public void addUserToLdap(User user) {
//        try {
//            // Create the DN for the user
//
//            //boolean userExists = ldapTemplate.exists(LdapQueryBuilder.query().where("uid").is(user.getUserName()));
//            Name userDn = LdapNameBuilder.newInstance(baseDn)
//                    .add("ou", "users")
//                    .add("cn", user.getUserName()) // Unique identifier (UID)
//                    .build();
//
//            // Define user attributes
//            Attributes userAttrs = new BasicAttributes();
//
//            userAttrs.put(new BasicAttribute("objectClass", "inetOrgPerson"));
//            userAttrs.put(new BasicAttribute("objectClass", "organizationalPerson"));
//            userAttrs.put(new BasicAttribute("cn", user.getUserName()));
//            userAttrs.put(new BasicAttribute("cn", user.getUserName())); // Common name
//            userAttrs.put(new BasicAttribute("sn", user.getUserName())); // Surname
//            //userAttrs.put(new BasicAttribute("mail", user.getEmail())); // Email
//            userAttrs.put(new BasicAttribute("userPassword", user.getPassword())); // Ensure it's hashed
//
////            String bcryptPassword = user.getPassword(); // The encoded password from registration
////
////            // Base64 encode the bcrypt password
////            String base64EncodedPassword = Base64.getEncoder().encodeToString(bcryptPassword.getBytes());
////
////            // Store the base64 encoded bcrypt password in the LDAP 'userPassword' attribute
////            userAttrs.put(new BasicAttribute("userPassword", base64EncodedPassword)); // Store Base64 encoded password
//
//
//            // Bind the user to LDAP (add the user)
//            ldapTemplate.bind(userDn, null, userAttrs);
////            ldapTemplate.unbind(userDn);
//            System.out.println("Successfully added user to LDAP: " + user.getUserName());
//        } catch (Exception e) {
//            System.out.println("Error adding user to LDAP: " + e.getMessage());
//        }
//    }

//public void addUserToLdap(User user) {
//    try {
//        // Create the DN for the user
//
//        //boolean userExists = ldapTemplate.exists(LdapQueryBuilder.query().where("uid").is(user.getUserName()));
//        Name userDn = LdapNameBuilder.newInstance(baseDn)
//                .add("ou", "users")
//                .add("cn", user.getUserName()) // Unique identifier (UID)
//                .build();
//
//        // Define user attributes
//        Attributes userAttrs = new BasicAttributes();
//
//        userAttrs.put(new BasicAttribute("objectClass", "inetOrgPerson"));
//        userAttrs.put(new BasicAttribute("objectClass", "organizationalPerson"));
//        userAttrs.put(new BasicAttribute("cn", user.getUserName()));
//        userAttrs.put(new BasicAttribute("cn", user.getUserName())); // Common name
//        userAttrs.put(new BasicAttribute("sn", user.getUserName())); // Surname
//        //userAttrs.put(new BasicAttribute("mail", user.getEmail())); // Email
//        userAttrs.put(new BasicAttribute("userPassword", user.getPassword())); // Ensure it's hashed
//
////            String bcryptPassword = user.getPassword(); // The encoded password from registration
////
////            // Base64 encode the bcrypt password
////            String base64EncodedPassword = Base64.getEncoder().encodeToString(bcryptPassword.getBytes());
////
////            // Store the base64 encoded bcrypt password in the LDAP 'userPassword' attribute
////            userAttrs.put(new BasicAttribute("userPassword", base64EncodedPassword)); // Store Base64 encoded password
//
//
//        // Bind the user to LDAP (add the user)
//        ldapTemplate.bind(userDn, null, userAttrs);
////            ldapTemplate.unbind(userDn);
//        System.out.println("Successfully added user to LDAP: " + user.getUserName());
//    } catch (Exception e) {
//        System.out.println("Error adding user to LDAP: " + e.getMessage());
//    }
//}

public void ensureBaseDnExists() {
    // Define the base DN
    String baseDn = "dc=example,dc=org";
    Name dn = LdapNameBuilder.newInstance(baseDn).build();

    try {
        // Try to look up the base DN
        ldapTemplate.lookup(dn);
        // If no exception, it exists
    } catch (org.springframework.ldap.NameNotFoundException e) {
        // Base DN doesn't exist, create it
        Attributes attrs = new BasicAttributes();
        BasicAttribute objectClass = new BasicAttribute("objectClass");
        objectClass.add("dcObject");
        objectClass.add("organization");
        attrs.put(objectClass);
        attrs.put(new BasicAttribute("dc", "example"));
        attrs.put(new BasicAttribute("o", "ExampleCorp"));

        try {
            ldapTemplate.bind(dn, null, attrs);
            System.out.println("Created base DN: " + baseDn);
        } catch (Exception ex) {
            System.err.println("Error creating base DN: " + ex.getMessage());
        }
    }
}

    /**
     * Adds a user to LDAP directory
     */
    public void addUserToLdap(User user) {
        // First ensure the base DN exists
        ensureBaseDnExists();

        // Define the base DN
        String baseDn = "dc=example,dc=org";

        // Create user DN properly under the base DN
        Name userDn = LdapNameBuilder.newInstance(baseDn)
                .add("uid", user.getUserName())
                .build();

        System.out.println("Adding user with DN: " + userDn.toString());

        Attributes userAttrs = new BasicAttributes();

        // Create a multi-valued attribute for objectClass - IMPORTANT
        BasicAttribute objectClass = new BasicAttribute("objectClass");
        objectClass.add("top");
        objectClass.add("person");
        objectClass.add("organizationalPerson");
        objectClass.add("inetOrgPerson");
        userAttrs.put(objectClass);

        // Add user attributes
        userAttrs.put(new BasicAttribute("uid", user.getUserName()));
        userAttrs.put(new BasicAttribute("cn", user.getUserName()));
        userAttrs.put(new BasicAttribute("sn", user.getUserName()));
        userAttrs.put(new BasicAttribute("mail", user.getEmail()));
//        String ldapPassword = "{BCRYPT}" + user.getPassword();

        userAttrs.put(new BasicAttribute("userPassword", user.getPassword()));

        try {
            // Check if user already exists
            try {
                ldapTemplate.lookup(userDn);
                // User exists, update it
                ldapTemplate.rebind(userDn, null, userAttrs);
                System.out.println("Updated existing user: " + user.getUserName());
            } catch (org.springframework.ldap.NameNotFoundException e) {
                // User doesn't exist, create it
                ldapTemplate.bind(userDn, null, userAttrs);
                System.out.println("Created new user: " + user.getUserName());
            }
        } catch (Exception e) {
            System.err.println("Error managing user in LDAP: " + e.getMessage());
            e.printStackTrace();
            throw e;
        }
    }

//    private boolean isUserInLdap(User user) {
//        try {
//            String searchFilter = "(uid=" + escapeForLdapFilter(user.getUserName()) + ")";
//
//            // Search for the user in LDAP
//            List<String> results = ldapTemplate.search(
//                    "ou=users,dc=example,dc=org", // Base DN for the users
//                    searchFilter,
//                    (AttributesMapper<String>) attributes -> (String) attributes.get("uid").get()
//            );
//
//            return !results.isEmpty(); // If the user exists, return true
//        } catch (Exception e) {
//            e.printStackTrace();
//            return false; // Return false if an error occurs (couldn't determine if user exists)
//        }
//    }

    private boolean isUserInLdap(User user) {
        try {
            String searchFilter = "(cn=" + escapeForLdapFilter(user.getUserName()) + ")";

            // Search for the user in LDAP
            List<String> results = ldapTemplate.search(
                    "ou=users,dc=example,dc=org", // Base DN for the users
                    searchFilter,
                    (AttributesMapper<String>) attributes -> (String) attributes.get("cn").get()
            );

            return !results.isEmpty(); // If the user exists, return true
        } catch (Exception e) {
            e.printStackTrace();
            return false; // Return false if an error occurs (couldn't determine if user exists)
        }
    }
}

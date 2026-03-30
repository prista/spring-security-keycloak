package com.drm.sandbox.security.security;

import org.springframework.jdbc.core.SqlParameter;
import org.springframework.jdbc.object.MappingSqlQuery;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import javax.sql.DataSource;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

public class JdbcUserDetailsService
        extends MappingSqlQuery<UserDetails>
        implements UserDetailsService {

    public JdbcUserDetailsService(DataSource ds) {
        super(ds, """
                select 
                u.c_username,
                up.c_password,
                array_agg(ua.c_authority) as authorities
                from t_user u
                left join t_user_password up on up.id_user = u.id
                left join t_user_authority ua on ua.id_user = u.id
                where u.c_username = :username
                group by u.id, up.id
                """);
        this.declareParameter(new SqlParameter("username", Types.VARCHAR));
        this.compile(); // to make that sqlQuery object immutable
    }

    @Override
    protected UserDetails mapRow(final ResultSet rs, final int rowNum) throws SQLException {
        return User.builder()
                .username(rs.getString("c_username"))
                .password(rs.getString("c_password"))
                .authorities((String[]) rs.getArray("authorities").getArray())
                .build();
    }

    @Override
    public UserDetails loadUserByUsername(final String username) throws UsernameNotFoundException {
        return Optional.ofNullable(this.findObjectByNamedParam(Map.of("username", username)))
                .orElseThrow(() -> new UsernameNotFoundException("Couldn't find user: " + username));
    }
}

package br.com.crm.moremac.config.securityConfig;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import br.com.crm.moremac.config.jwt.JWTAutenticarFilter;
import br.com.crm.moremac.config.jwt.JWTValidarFilter;
import br.com.crm.moremac.services.UsuarioService;



@SuppressWarnings("deprecation")
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	private UsuarioService userService;

	public SecurityConfig(@Lazy UsuarioService userService) {
		this.userService = userService;
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(userService).passwordEncoder(passwordEncoder());
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.cors().and().csrf().disable().authorizeRequests().antMatchers("/login").permitAll().anyRequest()
				.authenticated().and().addFilter(new JWTAutenticarFilter(authenticationManager(), userService))
				.addFilter(new JWTValidarFilter(authenticationManager(), userService)).sessionManagement()
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
	}

	@Override
	public void configure(WebSecurity web) throws Exception {
		web.ignoring().antMatchers("/users/forgot_password*").antMatchers("/users/reset_password*")
				.antMatchers("/usuarios/login*").antMatchers("/swagger-ui/**", "/v3/api-docs/**");
	}

}

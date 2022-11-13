package br.com.crm.moremac.config.jwt;

import java.io.IOException;
import java.util.ArrayList;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

public class JWTValidarFilter extends BasicAuthenticationFilter {

	public JWTValidarFilter(AuthenticationManager authenticationManager) {
		super(authenticationManager);
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {

		String authorization = request.getHeader(JWTConstants.HEADER_ATRIBUTO);

		if (authorization != null && !authorization.startsWith(JWTConstants.ATRIBUTO_PREFIXO)) {
			chain.doFilter(request, response);
			return;
		}

		String token = authorization.replace(JWTConstants.ATRIBUTO_PREFIXO, "");

		UsernamePasswordAuthenticationToken authenticationToken = getAuthenticationToken(token);

		SecurityContextHolder.getContext().setAuthentication(authenticationToken);
		chain.doFilter(request, response);
	}

	private UsernamePasswordAuthenticationToken getAuthenticationToken(String token) {
		String usuario = JWT.require(Algorithm.HMAC512(JWTConstants.CHAVE_ASSINATURA)).build().verify(token)
				.getSubject();

		if (usuario == null) {
			return null;
		}
		return new UsernamePasswordAuthenticationToken(usuario, null, new ArrayList<>());
	}

}

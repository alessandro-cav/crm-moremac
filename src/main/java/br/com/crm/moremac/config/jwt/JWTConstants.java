package br.com.crm.moremac.config.jwt;

public class JWTConstants {
	
	public static final int TOKEN_EXPIRADO = 86400000;

	public static final String CHAVE_ASSINATURA = "YSBsZWJyZSDDqSBicmFuY2E=";

	public static final String HEADER_ATRIBUTO = "Authorization";

	public static final String ATRIBUTO_PREFIXO = "Bearer ";

	public static final int TOKEN_EXPIRADO_ESQUECI_SENHA = 1800000;

	public static final String LINK_TOKEN_RESETAR_SENHA = "http://localhost:8080/cvv-back/users/reset_password?token=";

	public static final String JWT = "JWT";

	public static final String AUTHORIZATION_HEADER = "Authorization";

	public static final String HEADER = "header";
	
	public static final String DIRETORIO = "br.com.cvv.back.";
	
	public static final String GLOBAL = "global" ; 
	
	public static final String ACESS_EVERYTHING = "accessEverything" ;
	
	public static final String SCHEME_BEARER = "bearer";
	
	public static final String BEARER_AUTHENTICATION = "Bearer Authentication";
	
	public static final String TITULO = "Venda de veiculos API REST";
	
	public static final String VERSAO = "1.0.0";

}

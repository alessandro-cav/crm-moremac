package br.com.crm.moremac.config.email;

import org.springframework.context.annotation.Configuration;
import org.springframework.mail.MailException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;

@Configuration
public class EnviaEmail {

	private final JavaMailSender javaMailSender;

	public EnviaEmail(JavaMailSender javaMailSender) {
		this.javaMailSender = javaMailSender;
	}


	public void enviarEmail(String destino, String nome, String link) {

		try {
			String titulo = "Redefinição de Senha";

			String conteudo = "Olá " + nome + ", Houve uma solicitação para alterar sua senha de email! \n\n "
					+ "Se você não fez essa solicitação, ignore este e-mail."
					+ "Caso contrário, clique neste link para alterar sua senha: \n\n" + "Link: " + link;

			SimpleMailMessage mensagem = new SimpleMailMessage();
			mensagem.setTo(destino);
			mensagem.setSubject(titulo);
			mensagem.setText(conteudo);

			javaMailSender.send(mensagem);
		} catch (MailException e) {
			throw new RuntimeException(e);
		}

	}

}

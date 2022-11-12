package br.com.crm.moremac.enuns;

public enum Status {

	ATIVO("ATIVO"), INATIVO("INATIVO");

	private String descricao;

	public static Status buscarStatus(String tipo) {
		Status status2 = null;
		for (Status status : Status.values()) {
			if (status.getDescricao().equals(tipo.toUpperCase())) {
				status2 = status;
			}
		}
		return status2;
	}

	private Status(String descricao) {
		this.descricao = descricao;
	}

	public String getDescricao() {
		return descricao;
	}
}
package crypto.ssa5.spec;

import java.security.spec.KeySpec;

import matrix.ModularMatrix;

public class SAA5SecretKeySpec implements KeySpec {
	private final SAA5ParameterSpec params;
	private final ModularMatrix key;

	SAA5SecretKeySpec(SAA5ParameterSpec params, ModularMatrix key) {
		this.params = params;
		this.key = key;
	}

	public final SAA5ParameterSpec getParams() {
		return params;
	}

	public final ModularMatrix getKey() {
		return key;
	}
}

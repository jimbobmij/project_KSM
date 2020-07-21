package crypto.ssa5.spec;

import matrix.ModularMatrix;

public final class SAA5SlavePublicKeySpec extends SAA5KeySpec {
	private final ModularMatrix yA;

	public SAA5SlavePublicKeySpec(SAA5ParameterSpec params, ModularMatrix yA) {
		super(params);
		this.yA = yA;
	}

	public final ModularMatrix yA() {
		return yA.clone();
	}

}

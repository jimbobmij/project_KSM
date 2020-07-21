package crypto.ssa5.spec;

import matrix.ModularMatrix;

public final class SAA5noSESlavePublicKeySpec extends SAA5KeySpec {
	private final ModularMatrix yA;

	public SAA5noSESlavePublicKeySpec(SAA5ParameterSpec params, ModularMatrix yA) {
		super(params);
		this.yA = yA;
	}

	public final ModularMatrix yA() {
		return yA.clone();
	}

}

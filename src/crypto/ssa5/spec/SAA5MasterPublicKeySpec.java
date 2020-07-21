package crypto.ssa5.spec;

import matrix.ModularMatrix;

public class SAA5MasterPublicKeySpec extends SAA5KeySpec {
	private final ModularMatrix[] yB2;
	private final ModularMatrix[] yB3;

	public SAA5MasterPublicKeySpec(SAA5ParameterSpec params, ModularMatrix[] yB2, ModularMatrix[] yB3) {
		super(params);
		this.yB2 = yB2;
		this.yB3 = yB3;
	}

	public ModularMatrix[] getYB2() {
		return yB2.clone();
	}

	public ModularMatrix[] getYB3() {
		return yB3.clone();
	}
}

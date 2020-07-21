package crypto.ssa5.spec;

import matrix.ModularMatrix;

public class SAA5SlavePrivateKeySpec extends SAA5KeySpec {
	private final ModularMatrix[] xA;

	public SAA5SlavePrivateKeySpec(SAA5ParameterSpec params, ModularMatrix[] xA) {
		super(params);
		this.xA = xA;
	}

	public final ModularMatrix[] getXA() {
		return xA.clone();
	}
}

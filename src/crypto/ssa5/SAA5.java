package crypto.ssa5;

import java.security.Provider;

public class SAA5 extends Provider {
	public SAA5() {
		super("SAA5", 1.0d, "Strong Asymmetric key Agreement 5");

		// Service of SSA5
		put("KeyPairGenerator.SAA5master", "crypto.ssa5.spi.SAA5MasterKeyPairGeneratorSpi");
		put("KeyPairGenerator.SAA5slave", "crypto.ssa5.spi.SAA5SlaveKeyPairGeneratorSpi");
		put("KeyAgreement.SAA5master", "crypto.saa5.spi.SAA5MasterKeyAgreementSpi");
		put("KeyAgreement.SAA5slave", "crypto.saa5.spi.SAA5SlaveKeyAgreementSpi");

	}

	@Override
	public double getVersion() {
		return 1.0;
	}

}

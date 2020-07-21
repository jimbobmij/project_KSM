package crypto.ssa5;

import java.security.Provider;

public class SAA5noSE extends Provider {
	public SAA5noSE() {
		super("SAA5noSE", 1.0d, "Strong Asymmetric key Agreement 5 no SE");

		// Service of SSA5
		put("KeyPairGenerator.SAA5noSEmaster", "crypto.ssa5.spi.SAA5noSEMasterKeyPairGeneratorSpi");
		put("KeyPairGenerator.SAA5noSEslave", "crypto.ssa5.spi.SAA5noSESlaveKeyPairGeneratorSpi");
		put("KeyAgreement.SAA5noSEmaster", "crypto.saa5.spi.SAA5noSEMasterKeyAgreementSpi");
		put("KeyAgreement.SAA5noSEslave", "crypto.saa5.spi.SAA5noSESlaveKeyAgreementSpi");

	}

	@Override
	public double getVersion() {
		return 1.0;
	}

}

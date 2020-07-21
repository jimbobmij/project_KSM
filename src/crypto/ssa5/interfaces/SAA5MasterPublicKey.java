package crypto.ssa5.interfaces;

import java.security.PublicKey;

import matrix.ModularMatrix;

public interface SAA5MasterPublicKey extends SAA5Key, PublicKey, Serializable {
	ModularMatrix[] getYB2();

	ModularMatrix[] getYB3();
}

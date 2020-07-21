package crypto.ssa5.interfaces;

import java.security.PublicKey;

import matrix.ModularMatrix;

public interface SAA5SlavePublicKey extends SAA5Key, PublicKey, Serializable {
	ModularMatrix getYA();
}

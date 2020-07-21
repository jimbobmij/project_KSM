package crypto.ssa5.interfaces;

import java.security.PrivateKey;

import matrix.ModularMatrix;

public interface SAA5SlavePrivateKey extends SAA5Key, PrivateKey, Serializable {
	ModularMatrix[] getXA();
}

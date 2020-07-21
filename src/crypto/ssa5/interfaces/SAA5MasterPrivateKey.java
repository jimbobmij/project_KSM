package crypto.ssa5.interfaces;

import java.security.PrivateKey;

import matrix.ModularMatrix;

public interface SAA5MasterPrivateKey extends SAA5Key, PrivateKey, Serializable {
	ModularMatrix getNB();

	ModularMatrix getXB();

}

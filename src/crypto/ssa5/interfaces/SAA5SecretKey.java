package crypto.ssa5.interfaces;

import javax.crypto.SecretKey;

import matrix.ModularMatrix;

public interface SAA5SecretKey extends SAA5Key, SecretKey, Serializable {
	ModularMatrix getKey();
}

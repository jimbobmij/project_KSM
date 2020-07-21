package matrix.generator.rule;

import java.math.BigInteger;
import java.util.Random;

import matrix.generator.ModMatGen;

/** Create rule of invertible Upper Triangular Matrix */
public final class InvertibleUTM extends CreateRule<BigInteger> {
	private final BigInteger mod;
	private final Random rd;

	public InvertibleUTM(Random random, BigInteger modulus) {
		if (random == null)
			throw new NullPointerException("random");
		if (modulus == null)
			throw new NullPointerException("mod");
		if (modulus.compareTo(BigInteger.ZERO) <= 0)
			throw new IllegalArgumentException("mod must be positive number.");

		rd = random;
		mod = modulus;
	}

	@Override
	public BigInteger createValue(int i, int j) {
		if (i == j)
			// Diagonal element mast be invertible.
			return ModMatGen.randomInvBInt(rd, mod);
		else if (i > j)
			return BigInteger.ZERO;
		else
			return ModMatGen.randomBInt(rd, mod);
	}
}

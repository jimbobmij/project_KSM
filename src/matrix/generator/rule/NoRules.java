package matrix.generator.rule;

import java.math.BigInteger;
import java.util.Random;

import matrix.generator.ModMatGen;

/**Create */
public class NoRules extends CreateRule<BigInteger> {
	private final BigInteger mod;
	private final Random rd;

	public NoRules(Random random, BigInteger modulus) {
		if (random == null)
			throw new NullPointerException("random");
		rd = random;
		mod = modulus;
	}

	@Override
	public BigInteger createValue(int i, int j) {
		return ModMatGen.randomBInt(rd, mod);
	}

}
package matrix.generator;

import java.math.BigInteger;
import java.util.Random;
import java.util.Vector;

import matrix.generator.rule.CreateRule;
import matrix.generator.rule.InvertibleLTM;
import matrix.generator.rule.InvertibleUTM;
import matrix.generator.rule.NoRules;
import matrix.ModularMatrix;

/** Modular Matrix Generator */
public class ModMatGen {
	/**
	 * Returns base <sup>exponent</sup> (mod modulus) <BR>
	 * 0<sup>0</sup>=0
	 *
	 * @throws IllegalArgumentException
	 *             modulus < 2
	 */
	public static BigInteger schurExp(BigInteger base, BigInteger exponent, BigInteger modulus) {
		if (modulus.compareTo(new BigInteger("2")) < 0)
			throw new IllegalArgumentException("mod must be gleater or equalsto 2.");

		if (base.equals(BigInteger.ZERO))
			return BigInteger.ZERO;
		else
			return base.modPow(exponent, modulus);
	}

	/**
	 * Randomly returns a value greater or equals to 'inf', lower than 'sup' by
	 * the method given the Random object in argument.
	 *
	 * @param random
	 *            The method to choose integer randomly.
	 * @param inf
	 *            An integer is randomly chosen from above the value of this
	 *            parameter.
	 * @param sup
	 *            An integer is randomly chosen from less than the value of this
	 *            parameter.
	 * @throws IllegalArgumentException
	 *             sup <= inf
	 */
	public static int randomInt(Random random, int inf, int sup) {
		if (!(inf < sup))
			throw new IllegalArgumentException("'inf' must be lower than 'sup'");
		return inf + random.nextInt(sup - inf);
	}

	/**
	 * Create an invertible ModularMatrix and it's inverse ModularMatrix.<BR>
	 * They are returned as an array in the order of the generated matrix and
	 * the inverse matrix.
	 *
	 * @param random
	 *            The method to choose integer randomly.
	 * @param dim
	 *            The size of matrix to be created.
	 * @param modulus
	 *            The modulus.
	 * @throws IllegalArgumentException
	 *             modulus < 2
	 */
	public static ModularMatrix[] makeInvertibleMatrix(Random random, int dim, BigInteger modulus) {
		if (modulus.compareTo(new BigInteger("2")) < 0)
			throw new IllegalArgumentException("mod must be gleater or equalsto 2.");

		ModularMatrix l = createMatrix(new InvertibleLTM(random, modulus), dim, modulus);
		ModularMatrix u = createMatrix(new InvertibleUTM(random, modulus), dim, modulus);

		// generate LTM inverse
		ModularMatrix li = generateLTMInv(l, modulus);

		// generate UTM inverse
		ModularMatrix ui = generateLTMInv(u.transpose(), modulus).transpose();

		ModularMatrix[] res = { l.multi(u), ui.multi(li) };
		return res;
	}

	private static ModularMatrix generateLTMInv(ModularMatrix ltm, BigInteger mod) {
		int dim = ltm.getRowSize();
		BigInteger[][] linv = new BigInteger[dim][dim];

		// set 1st row
		for (int j = 0; j < dim; j++) {
			if (0 == j)
				linv[0][j] = BigInteger.ONE;
			else
				linv[0][j] = BigInteger.ZERO;
		}

		for (int i = 0; i < dim; i++)
			for (int j = 0; j < dim; j++) {
				// divide ith row of L' by L[i,i]
				linv[i][j] = linv[i][j].multiply(ltm.get(i, i).modInverse(mod));

				if (i < dim - 1) {
					if (i + 1 == j)
						linv[i + 1][j] = BigInteger.ONE;
					else
						linv[i + 1][j] = BigInteger.ZERO;

					for (int k = j; k < i + 1; k++)
						// L'[i+1,j] = L'[i+1,j] - L[i+1,k] * L'[k,j]
						linv[i + 1][j] = linv[i + 1][j].subtract(ltm.get(i + 1, k).multiply(linv[k][j]));
				}
			}
		return new ModularMatrix(linv, mod);
	}

	/**
	 * Create an not invertible ModularMatrix.
	 *
	 * @param random
	 *            The method to choose integer randomly.
	 * @param dim
	 *            The size of matrix to be created.
	 * @param mod
	 *            The modulus.
	 * @throws IllegalArgumentException
	 *             modulus < 2
	 */
	public static ModularMatrix makeNotInvertibleMatrix(Random random, int dim, BigInteger modulus) {
		if (modulus.compareTo(new BigInteger("2")) < 0)
			throw new IllegalArgumentException("mod must be gleater or equalsto 2.");
		if (dim < 2)
			throw new IllegalArgumentException("'d' must be larger than 2.");

		BigInteger[][] data = new BigInteger[dim][dim];
		for (int i = 0; i < dim; i++)
			for (int j = 0; j < dim; j++)
				if (i == j)
					data[i][j] = BigInteger.ZERO;
				else
					data[i][j] = ModMatGen.randomBInt(random, modulus);

		return new ModularMatrix(data, modulus);
	}

	/* create a matrix accordance with given "create rule" */
	public static ModularMatrix createMatrix(CreateRule<BigInteger> cr, int dim, BigInteger mod) {
		BigInteger[][] res = new BigInteger[dim][dim];

		for (int i = 0; i < dim; i++)
			for (int j = 0; j < dim; j++)
				res[i][j] = cr.createValue(i, j);

		return new ModularMatrix(res, mod);
	}

	/**
	 * Randomly return a positive BigInteger less than argument.
	 *
	 * @param random
	 *            The method to choose integer randomly.
	 * @throws IllegalArgumentException
	 *             modulus < 2
	 **/
	public static BigInteger randomBInt(Random random, BigInteger modulus) {
		if (modulus.compareTo(new BigInteger("2")) < 0)
			throw new IllegalArgumentException("mod must be gleater or equalsto 2.");

		BigInteger res;
		BigInteger MAX = new BigInteger(Integer.toString(Integer.MAX_VALUE));

		if (modulus.compareTo(MAX) > 0) {
			BigInteger m = modulus;
			Vector<Integer> v = new Vector<Integer>();

			// Split biginteger into size of integer.
			while (!m.equals(BigInteger.ZERO)) {
				v.add(random.nextInt(m.mod(MAX).intValue()));
				m = m.divide(MAX);
			}

			res = BigInteger.ZERO;
			int cnt = 0;

			// Assembling the cut value again
			for (Integer b : v) {
				res = res.add(new BigInteger(b.toString()).multiply(MAX.pow(cnt)));
				cnt++;
			}

			return res;
		} else if (modulus.compareTo(BigInteger.ZERO) > 0) {
			// In case of mod < IntMAX
			do
				res = new BigInteger(Integer.toString(random.nextInt(modulus.intValue())));
			while (res.equals(BigInteger.ZERO));
			return res;
		} else
			throw new IllegalArgumentException("'mod' must be greater than 0.");
	}

	/**
	 * Randomly return a positive BigInteger less than argument.
	 *
	 * @param random
	 *            The method to choose integer randomly.
	 * @throws IllegalArgumentException
	 *             modulus < 2
	 **/
	public static BigInteger randomInvBInt(Random random, BigInteger modulus) {
		if (modulus.compareTo(new BigInteger("2")) < 0)
			throw new IllegalArgumentException("mod must be gleater or equalsto 2.");
		while (true) {
			try {
				return ModMatGen.randomBInt(random, modulus).modInverse(modulus);
			} catch (ArithmeticException e) {
				// not invertible. try again.
			}
		}
	}

	private long extGCD(long a, long b, int x, int y) {
		if (b == 0) {
			x = 1;
			y = 0;
			return a;
		} else {
			long d = extGCD(b, a % b, y, x);
			y -= a / b * x;
			return d;
		}
	}
}

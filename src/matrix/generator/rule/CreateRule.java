package matrix.generator.rule;

/** Describe How to determine a_{ij} in Matrix A */
public abstract class CreateRule<E extends Comparable<E>> {

	/**
	 * Returns the ij element of the matrix according to the specified
	 * production rule.
	 *
	 * @param i
	 *            row of a matrix.
	 * @param j
	 *            column of a matrix.
	 * @param element
	 *
	 */
	@SuppressWarnings("unchecked")
	public abstract E createValue(int i, int j);

}

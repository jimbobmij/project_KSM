package crypto.ssa5.spi;

public class NotEnoughByteSizeException extends RuntimeException {

	public NotEnoughByteSizeException(String massage) {
		super(massage);
	}
}

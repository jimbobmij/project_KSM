package crypto.ssa5.spi;

import java.math.BigInteger;
import java.util.Arrays;

import crypto.ssa5.interfaces.Serializable;

public class ByteArrayConverter {
	public static final int INTEGER_BYTES = Integer.SIZE / Byte.SIZE;

	public static void main(String args[]) {
		BigInteger i = new BigInteger("12345678901234567890");
		System.out.println(i.bitLength());

		System.out.println(Arrays.toString(i.toByteArray()));

		byte[] array = new byte[10];

		saveBInt(array, 0, i, 10);
		System.out.println(Arrays.toString(array));
		System.out.println(loadBInt(array, 0, 10));
	}

	public static int byteLength(int bitLength) {
		// include sign bit
		return ((bitLength + 1) + 7) / 8;
	}

	public static void saveByte(byte[] array, int pos, int val) {
		array[pos] = (byte) (val & 0xFF);
	}

	public static int loadByte(byte[] array, int pos) {
		return array[pos] & 0xFF;
	}

	public static void saveShort(byte[] array, int pos, int val) {
		array[pos + 0] = (byte) (val & 0xFF);
		array[pos + 1] = (byte) ((val >>> 8) & 0xFF);
	}

	public static int loadShort(byte[] array, int pos) {
		int res = (array[pos + 0] & 0xFF);
		res += (array[pos + 1] & 0xFF) << 8;
		return res;
	}

	public static void saveInt(byte[] array, int pos, int val) {
		array[pos + 0] = (byte) (val & 0xFF);
		array[pos + 1] = (byte) ((val >>> 8) & 0xFF);
		array[pos + 2] = (byte) ((val >>> 16) & 0xFF);
		array[pos + 3] = (byte) ((val >>> 24) & 0xFF);
	}

	public static int loadInt(byte[] array, int pos) {
		int res = (array[pos + 0] & 0xFF);
		res += (array[pos + 1] & 0xFF) << 8;
		res += (array[pos + 2] & 0xFF) << 16;
		res += (array[pos + 3] & 0xFF) << 24;
		return res;
	}

	public static void saveBInt(byte[] array, int pos, BigInteger bint, int byteLength) {
		// include sign bit
		int valLength = byteLength(bint.bitLength());
		if (pos + valLength > array.length)
			throw new ArrayLengthNotEnoughException(array.length + " (" + (pos + valLength) + ")");

		if (valLength > byteLength)
			throw new ArrayLengthNotEnoughException(pos + byteLength + " (" + pos + valLength + ")");

		byte[] bintAllay = bint.toByteArray();
		int j = 0;
		for (int i = 0; i < byteLength; i++)
			if (byteLength - i > valLength) {
				// padding
				array[pos + i] = 0;
			} else {
				array[pos + i] = bintAllay[j];
				j++;
			}
	}

	public static BigInteger loadBInt(byte[] array, int pos, int byteLength) {
		// include sign bit
		if (pos + byteLength > array.length)
			throw new ArrayLengthNotEnoughException(array.length + " (" + (pos + byteLength) + ")");

		byte[] res = new byte[byteLength];
		for (int i = 0; i < byteLength; i++)
			res[i] = array[pos + i];
		return new BigInteger(res);
	}

	public static <E extends Serializable> int saveElem(byte[] array, int pos, E elem) {
		copyToArray(array, pos, elem.toByteArray());
		return elem.byteArrayLength();
	}

	public static <E extends Serializable> byte[] arrayToBytes(E[] array) {
		int length = 0;
		for (E elem : array)
			length += elem.byteArrayLength();

		int pos = 0;
		byte[] res = new byte[length];
		for (int i = 0; i < array.length; i++)
			pos += saveElem(res, pos, array[i]);
		return res;
	}

	public static void copyToArray(byte[] array, int startPos, byte[] srcArray) {
		for (int i = 0; i < srcArray.length; i++)
			array[startPos + i] = srcArray[i];
	}

	public static byte[] cutOutArray(byte[] srcArray, int pos, int length) {
		byte[] res = new byte[length];
		for (int i = 0; i < length; i++)
			res[length] = srcArray[pos + i];
		return res;
	}
}

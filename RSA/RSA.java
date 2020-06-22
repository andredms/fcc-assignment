/****************************************
* AUTHOR: Andre de Moeller              
* DATE: 06.05.20						
* PURPOSE: implements RSA               
* LAST MODIFIED: 17.05.20
****************************************/
import java.util.*;
import java.io.*;
import java.math.*;

public class RSA {

	/****************************************
	* NAME: encrypt						
	* IMPORT: filename, public key, n					
	* EXPORT: none							
	* PURPOSE: encrypts characters in file						
	****************************************/
	public static void encrypt(String filename, long pubKey, long n) {
		long ch = 0;
		BufferedReader reader = null;
		FileOutputStream fileStrm = null;
		PrintWriter pw;

		try {
			reader = new BufferedReader(new FileReader(filename));

			fileStrm = new FileOutputStream("ciphertext.txt");
			pw = new PrintWriter(fileStrm);
			int count = 0;
			ch = reader.read();

			//loop until -1 is read 
			while (ch != -1) {
				//encrypt character 
				ch = fme(ch, pubKey, n);

				//print to file
				pw.print(ch + " ");

				//read next character
				ch = reader.read();
			}
			pw.close();
			reader.close();

			System.out.println("Encryption: ciphertext.txt ");
			System.out.println(".................................................");
		}
		catch(IOException e) {
			if (fileStrm == null) {
				System.out.println("Invalid!");
			}
		}
	}

	/****************************************
	* NAME: decrypt						
	* IMPORT: filename, private key, n					
	* EXPORT: none							
	* PURPOSE: decrypts characters in file						
	****************************************/
	public static void decrypt(String filename, long privKey, long n) {
		long ch = 0;
		BufferedReader reader = null;
		FileOutputStream fileStrm = null;
		String line;
		String[] arr;

		PrintWriter pw;

		try {
			reader = new BufferedReader(new FileReader(filename));
			fileStrm = new FileOutputStream("plaintext.txt");
			pw = new PrintWriter(fileStrm);

			line = reader.readLine();
			//loop until null
			while (line != null) {
				//fill array with long numbers (seperated by space in encryption)
				arr = line.split(" ");

				for (int ii = 0; ii < arr.length; ii++) {
					//convert character at ii in line to long
					ch = Long.parseLong(arr[ii]);

					//decrypt character
					ch = fme(ch, privKey, n);
					pw.print((char) ch);
				}
				line = reader.readLine();
			}
			pw.close();
			reader.close();
			System.out.println("Decryption: plaintext.txt ");
			System.out.println(".................................................");
		}
		catch(IOException e) {
			if (fileStrm == null) {
				System.out.println("Invalid!");
			}
		}
	}
	/****************************************
	* NAME: randPrime					
	* IMPORT: a, b						
	* EXPORT: random prime				
	* PURPOSE: generate random prime		
	****************************************/
	public static long randPrime(int min, int max) {
		Random rand = new Random();
		boolean isPrime = false;
		long num = 0;

		//until a prime number is found
		while (!isPrime) {
			//get a random number between min and max
			num = rand.nextInt((max - min) + 1) + min;

			//check if random number is prime
			if (lehman(num)) {
				isPrime = true;
			}
		}

		return num;
	}

	/****************************************
	* NAME: lehman						
	* IMPORT: p							
	* EXPORT: b (prime or not)			
	* PURPOSE: check if number is prime		
	****************************************/
	private static boolean lehman(long p) {
		Random rand = new Random();
		int a,
		exponent;
		long r;
		boolean negFound = false;

		if (p == 2) {
			//2 is the only even prime number
			return true;
		}
		else if (p % 2 == 0) {
			//no even numbers (except 2) can be prime
			return false;
		}
		//looping 100 times increases reliability
		for (int ii = 0; ii < 100; ii++) {
			//generates random number between 2 and p
			//fermat's little theorem
			a = rand.nextInt(((int) p - 2) + 1) + 2;

			exponent = (((int) p - 1) / 2);

			//mod pow
			r = fme(a, exponent, p);

			if (r != 1 && r != -1) {
				r = r - p;
				if (r != -1) {
					//not a prime
					return false;
				}
			}
			if (r == -1) {
				//not a prime
				negFound = true;
			}
		}
		if (!negFound) {
			//not a prime
			return false;
		}
		else {
			//is a prime
			return true;
		}

	}

	/****************************************
	* NAME: getPublic					
	* IMPORT: filename					
	* EXPORT: none						
	* PURPOSE: finds the public key			
	****************************************/
	public static long getPublic(long n, long phi) {
		//e has to be greater than 1 
		long e = 2;
		boolean found = false;

		//e has to be less than phi
		while (e < phi && !found) {
			//if numbers are coprime
			if (gcd(e, phi) == 1) {
				found = true;
			}
			else {
				//increment public key
				e++;
			}
		}
		return e;
	}

	/****************************************
	* NAME: gcd 							
	* IMPORT: filename					
	* EXPORT: none   					
	* PURPOSE: finds gcd					
	****************************************/
	public static long gcd(long a, long b) {
		if (b == 0) {
			return a;
		}
		return gcd(b, a % b);
	}

	/****************************************
	* NAME: extendedEuclid						
	* IMPORT: filename						
	* EXPORT: lastx							
	* PURPOSE: gets private key				
	****************************************/
	public static long extendedEuclid(long a, long n) {
		long temp = 0,
		quotient,
		lastx = 1,
		lasty = 0,
		x = 0,
		y = 1,
		tempX,
		tempY,
		origN = n;

		//0 = gcd found
		while (n != 0) {
			//regular euclidian algorithm
			temp = n;
			quotient = a / n;
			n = a % n;
			a = temp;

			//extended algorithm
			tempX = x;
			x = lastx - quotient * x;
			lastx = tempX;

			tempY = y;
			y = lasty - quotient * y;
			lasty = tempY;
		}
		if (lastx < 0) {
			lastx = origN + lastx;
		}

		return lastx;
	}

	/****************************************
	* NAME: fme (fast modular exponent)		
	* IMPORT: base, exp, mod				
	* EXPORT: f	
	* PURPOSE:						    
	* REFERENCE: Cryptography and Network Security - Principals 
    	*            and practice (6th edition), page: 269
	****************************************/
	public static long fme(long base, long exponent, long modulus) {
		//convert exponent to array of bits
		long bits[] = longBin(exponent);

		//BigInteger used as longs are too small
		BigInteger result = BigInteger.valueOf(1);
		BigInteger baseBig = BigInteger.valueOf(base);
		BigInteger exponentBig = BigInteger.valueOf(exponent);
		BigInteger modBig = BigInteger.valueOf(modulus);

		for (int ii = 0; ii < bits.length; ii++) {
			result = (result.multiply(result)).mod(modBig);
			if (bits[ii] == 1) {
				result = (result.multiply(baseBig)).mod(modBig);
			}
		}
		return result.longValue();
	}

	/****************************************
	* NAME: longBin	
	* IMPORT: exponent				
	* EXPORT: bits array
	* PURPOSE: convert exponent to base 2			    
	****************************************/
	public static long[] longBin(long exponent) {
		//convert exponent to binary string
		String binStr = Long.toBinaryString(exponent);
		int len = binStr.length();

		//create array size of binary string
		long[] bits = new long[len];

		//fill each index with the numeric value of ii 
		for (int ii = 0; ii < len; ii++) {
			bits[ii] = Character.getNumericValue(binStr.charAt(ii));
		}
		return bits;
	}

}

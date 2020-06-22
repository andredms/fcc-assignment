/****************************************
 * AUTHOR: Andre de Moeller              *
 * DATE: 06.05.20
 * PURPOSE:                              *
 * LAST MODIFIED: 17.05.20
 ****************************************/
import java.util. * ;
import java.io. * ;

public class run {
	public static void main(String[] args) {
		//random number prime range 
		public static final int MIN = 10000;
		public static final int MAX = 100000;

		public static void main(String[] args) {
			String filename;
			long p,
			q,
			n,
			phi,
			pubKey,
			privKey;

			Scanner sc = new Scanner(System. in );
			System.out.println("-------------------------------------------------");
			System.out.println("                        RSA                      ");
			System.out.println("-------------------------------------------------");

			System.out.println("Enter filename: ");
			System.out.println(".................................................");

			filename = sc.nextLine();
			System.out.println(".................................................");

			//KEY GENERATION
			//find two large prime numbers (private)
			p = RSA.randPrime(MIN, MAX);
			q = RSA.randPrime(MIN, MAX);

			//if q == p, the encryption is weakened
			while (q == p) {
				q = RSA.randPrime(MIN, MAX);
			}

			//modulus in encryption key (public)
			n = p * q;

			//calculate phi (Φ)
			phi = (p - 1) * (q - 1);

			//asymmetric system means that a keypair is generated (public and private)
			//get public key, must be 1 < e < Φ and coprime with n and Φ
			pubKey = RSA.getPublic(n, phi);

			//get private key
			privKey = RSA.extendedEuclid(pubKey, phi);

			//ENCRYPT/DECRYPT
			RSA.encrypt(filename, pubKey, n);
			RSA.decrypt("ciphertext.txt", privKey, n);
		}
	}
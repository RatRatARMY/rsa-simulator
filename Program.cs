using System;
using System.Numerics;
using System.Security.Cryptography;

class RSAKeyGen
{
    static void Main()
    {
        Console.Write("Nhập số nguyên tố p: ");
        if (!ulong.TryParse(Console.ReadLine(), out ulong p) || !IsPrime(p))
        {
            Console.WriteLine("❌ p không hợp lệ hoặc không phải số nguyên tố.");
            return;
        }

        Console.Write("Nhập số nguyên tố q: ");
        if (!ulong.TryParse(Console.ReadLine(), out ulong q) || !IsPrime(q))
        {
            Console.WriteLine("❌ q không hợp lệ hoặc không phải số nguyên tố.");
            return;
        }

        if (p == q)
        {
            Console.WriteLine("❌ p và q không được giống nhau.");
            return;
        }

        int bitLenP = (int)Math.Floor(BigInteger.Log(p, 2)) + 1;
        int bitLenQ = (int)Math.Floor(BigInteger.Log(q, 2)) + 1;

        if (bitLenP != bitLenQ)
        {
            Console.WriteLine("❌ p và q phải có cùng độ dài theo bit.");
            return;
        }

        int decLenP = p.ToString().Length;
        int decLenQ = q.ToString().Length;

        if (Math.Abs(decLenP - decLenQ) < 1)
        {
            Console.WriteLine("❌ p và q phải khác nhau một vài chữ số (về độ dài thập phân).");
            return;
        }

        // Bước 2: Tính n = p × q
        BigInteger n = (BigInteger)p * q;

        // Bước 3: Tính λ(n) = BCNN(p - 1, q - 1) (bội chung nhỏ nhất)
        BigInteger lambda = BoiChungNhoNhat(p - 1, q - 1);

        // Bước 4: Chọn e ngẫu nhiên sao cho ƯCLN(e, lambda) == 1 (ước chung lớn nhất)
        BigInteger e = GenerateRandomCoprime(lambda, maxAttempts: int.MaxValue);
        if (e == -1)
        {
            Console.WriteLine("❌ Không tìm được e phù hợp trong số lần thử giới hạn.");
            return;
        }

        // Bước 5: Tính d = e⁻¹ mod lambda
        BigInteger d = ModInverse(e, lambda);

        // ✅ Kết quả
        Console.WriteLine("\n📦 Public Key (n, e):");
        Console.WriteLine($"n = {n}");
        Console.WriteLine($"e = {e}");

        Console.WriteLine("\n🔐 Private Key (n, d):");
        Console.WriteLine($"n = {n}");
        Console.WriteLine($"d = {d}");
    }

    static bool IsPrime(ulong number)
    {
        if (number < 2) return false;
        if (number == 2 || number == 3) return true;
        if (number % 2 == 0) return false;
        ulong limit = (ulong)Math.Sqrt(number);
        for (ulong i = 3; i <= limit; i += 2)
        {
            if (number % i == 0) return false;
        }
        return true;
    }

    static BigInteger UocChungLonNhat(BigInteger a, BigInteger b)
    {
        while (b != 0)
        {
            BigInteger t = b;
            b = a % b;
            a = t;
        }
        return a;
    }

    static BigInteger BoiChungNhoNhat(BigInteger a, BigInteger b)
    {
        return (a * b) / UocChungLonNhat(a, b);
    }

    static BigInteger ModInverse(BigInteger a, BigInteger m)
    {
        BigInteger m0 = m, t, q;
        BigInteger x0 = 0, x1 = 1;

        if (m == 1) return 0;

        while (a > 1)
        {
            q = a / m;
            t = m;
            m = a % m;
            a = t;

            t = x0;
            x0 = x1 - q * x0;
            x1 = t;
        }

        if (x1 < 0) x1 += m0;

        return x1;
    }

    static BigInteger GenerateRandomCoprime(BigInteger max, int maxAttempts)
    {
        int bits = (int)Math.Floor(BigInteger.Log(max, 2)) + 1;
        RandomNumberGenerator rng = RandomNumberGenerator.Create();
        byte[] buffer = new byte[(bits + 7) / 8];

        for (int i = 0; i < maxAttempts; i++)
        {
            rng.GetBytes(buffer);
            BigInteger candidate = new BigInteger(buffer);
            candidate = BigInteger.Abs(candidate % (max - 1)) + 1; // đảm bảo 1 ≤ e < lambda

            if (UocChungLonNhat(candidate, max) == 1)
            {
                return candidate;
            }
        }

        return -1; // Không tìm được giá trị phù hợp
    }
}

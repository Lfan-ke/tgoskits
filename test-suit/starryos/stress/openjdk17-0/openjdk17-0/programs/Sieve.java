public class Sieve {
    public static void main(String[] args) {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 1000;
        boolean[] composite = new boolean[n + 1];
        int count = 0;
        for (int i = 2; i <= n; i++) {
            if (composite[i]) continue;
            count++;
            for (long j = (long) i * i; j <= n; j += i) composite[(int) j] = true;
        }
        System.out.println("primes_up_to=" + n + " count=" + count);
        if (n == 1000 && count != 168) throw new AssertionError("expected 168, got " + count);
    }
}

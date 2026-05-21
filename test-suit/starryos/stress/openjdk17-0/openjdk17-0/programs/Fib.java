public class Fib {
    static long fib(int n) {
        return n < 2 ? n : fib(n - 1) + fib(n - 2);
    }
    public static void main(String[] args) {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 25;
        long t0 = System.nanoTime();
        long v = fib(n);
        long t1 = System.nanoTime();
        System.out.println("fib(" + n + ")=" + v + " in " + (t1 - t0) / 1_000_000 + "ms");
        if (n == 25 && v != 75025L) throw new AssertionError("expected 75025, got " + v);
    }
}

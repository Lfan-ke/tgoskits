import java.util.concurrent.atomic.AtomicLong;

public class ThreadTest {
    public static void main(String[] args) throws InterruptedException {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 4;
        int per = 100_000;
        AtomicLong sum = new AtomicLong();
        Thread[] ts = new Thread[n];
        for (int i = 0; i < n; i++) ts[i] = new Thread(() -> {
            long s = 0;
            for (int k = 1; k <= per; k++) s += k;
            sum.addAndGet(s);
        });
        for (Thread t : ts) t.start();
        for (Thread t : ts) t.join();
        long expected = (long) n * per * (per + 1L) / 2L;
        System.out.println("threads=" + n + " sum=" + sum.get() + " expected=" + expected);
        if (sum.get() != expected) throw new AssertionError("sum mismatch");
    }
}

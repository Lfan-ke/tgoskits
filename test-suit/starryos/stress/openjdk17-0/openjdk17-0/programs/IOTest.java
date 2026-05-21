import java.nio.file.*;
import java.security.MessageDigest;

public class IOTest {
    public static void main(String[] args) throws Exception {
        Path p = Paths.get("/tmp/iotest.bin");
        byte[] buf = new byte[64 * 1024];
        for (int i = 0; i < buf.length; i++) buf[i] = (byte) (i * 31);
        Files.write(p, buf, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        byte[] back = Files.readAllBytes(p);
        if (back.length != buf.length) throw new AssertionError("len mismatch");
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] h = md.digest(back);
        StringBuilder sb = new StringBuilder();
        for (byte b : h) sb.append(String.format("%02x", b));
        System.out.println("io_bytes=" + back.length + " sha256=" + sb);
        Files.delete(p);
    }
}

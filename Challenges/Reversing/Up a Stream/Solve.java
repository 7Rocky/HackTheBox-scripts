import java.util.Arrays;

public class Solve {
  public static void main(String[] args) {
    if (args.length != 1) {
      System.out.println("Usage: java Solve.java <output-string>");
      System.exit(1);
    }

    System.out.println(Solve.reverseDunkTheFlag(args[0]));
  }

  private static String reverseDunkTheFlag(String s) {
    return Arrays.asList(s.substring(4 * s.length() / 5).split("O"))
      .stream()
      .map(h -> Integer.valueOf(h, 16))
      .map(Solve::undilute)
      .map(Solve::undrench)
      .map(Solve::unmoisten)
      .map(n -> Character.toString((char) (int) n))
      .reduce("", (s1, s2) -> s2 + s1);
  }

  private static Integer unmoisten(int n) {
    return (int) (n % 2 == 0 ? (double) n : Math.sqrt(n));
  }

  private static Integer undrench(Integer n) {
    return n >> 1;
  }

  private static Integer undilute(Integer n) {
    return n * 2 / 3;
  }
}

class aa {
        int a = 6;

        int debug(int a, int b)
        {
                int sum;

                sum = a + b;

                return sum;
        }
}

public class test {
        public static void main(String args[]) {
                int a;

                aa bb = new aa();
                a = bb.debug(1, 2);
        }
}

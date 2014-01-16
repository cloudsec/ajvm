public class test1 {
        static int sub(int value)
        {
                int a = 1;

                return value - 1;
        }

        static int add(int a, int b)
        {
                int sum = 0;
                int c;

                sum = a + b;

                c = sub(sum);

                return c;
        }

        public static void main(String args[]) {
                int a = 1, b = 2;
                int ret;

                ret = add(a, b);
                return ;
        }
}

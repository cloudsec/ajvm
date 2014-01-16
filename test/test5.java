public class test5 {
        public static void main(String args[]) {
                long a = 0xabc12345678L;
		long b = 0xcba87654321L;
                long ret;

		if (a > b)
			ret = a;
		else
			ret = b;

                return ;
        }
}

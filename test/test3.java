public class test3 {
        public static void main(String args[]) {
                int a = 1, b = 2, c= 3, d = 4;
                int ret = -1;

		if (a > b) {
			if (c > d) {
				ret = 100;
			}
			else {
				ret = 101;
			}
		}
		else if (a == b) {
			ret = 102;
		}
		else {
			if (c > d) {
				ret = 103;
			}
			else {
				if (ret == 0)
					ret = 105;
				else
					ret = 104;
			}
		}

                return ;
        }
}

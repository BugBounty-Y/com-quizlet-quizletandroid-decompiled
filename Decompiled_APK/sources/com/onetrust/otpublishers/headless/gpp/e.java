package com.onetrust.otpublishers.headless.gpp;

import java.util.regex.Pattern;

/* loaded from: classes2.dex */
public abstract class e {
    public static final Pattern a = Pattern.compile("^[0-1]*$", 2);

    public static String a(int i, int i2) {
        StringBuilder sb = new StringBuilder();
        while (true) {
            String str = "0";
            if (i <= 0) {
                break;
            }
            if ((i & 1) == 1) {
                str = "1";
            }
            sb.insert(0, str);
            i >>= 1;
        }
        while (sb.length() < i2) {
            sb.insert(0, "0");
        }
        return sb.toString();
    }
}

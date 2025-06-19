package com.google.android.gms.internal.ads;

import java.util.regex.Pattern;

/* renamed from: com.google.android.gms.internal.ads.y2, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2854y2 {
    public static final Pattern c = Pattern.compile("\\[voice=\"([^\"]*)\"\\]");
    public static final Pattern d = Pattern.compile("^((?:[0-9]*\\.)?[0-9]+)(px|em|%)$");
    public final Kn a = new Kn();
    public final StringBuilder b = new StringBuilder();

    public static String a(Kn kn, StringBuilder sb) {
        b(kn);
        if (kn.s() == 0) {
            return null;
        }
        String strC = c(kn, sb);
        if (!"".equals(strC)) {
            return strC;
        }
        char cZ = (char) kn.z();
        StringBuilder sb2 = new StringBuilder();
        sb2.append(cZ);
        return sb2.toString();
    }

    public static void b(Kn kn) {
        while (true) {
            for (boolean z = true; kn.s() > 0 && z; z = false) {
                int i = kn.b;
                byte[] bArr = kn.a;
                byte b = bArr[i];
                char c2 = (char) b;
                if (c2 == '\t' || c2 == '\n' || c2 == '\f' || c2 == '\r' || c2 == ' ') {
                    kn.k(1);
                } else {
                    int i2 = kn.c;
                    if (i + 2 <= i2) {
                        int i3 = i + 1;
                        if (b == 47) {
                            int i4 = i + 2;
                            if (bArr[i3] == 42) {
                                while (true) {
                                    int i5 = i4 + 1;
                                    if (i5 >= i2) {
                                        break;
                                    }
                                    if (((char) bArr[i4]) == '*' && ((char) bArr[i5]) == '/') {
                                        i2 = i4 + 2;
                                        i4 = i2;
                                    } else {
                                        i4 = i5;
                                    }
                                }
                                kn.k(i2 - kn.b);
                            }
                        } else {
                            continue;
                        }
                    }
                }
            }
            return;
        }
    }

    public static String c(Kn kn, StringBuilder sb) {
        boolean z;
        char c2;
        sb.setLength(0);
        int i = kn.b;
        int i2 = kn.c;
        loop0: while (true) {
            for (false; i < i2 && !z; true) {
                c2 = (char) kn.a[i];
                z = (c2 < 'A' || c2 > 'Z') && (c2 < 'a' || c2 > 'z') && !((c2 >= '0' && c2 <= '9') || c2 == '#' || c2 == '-' || c2 == '.' || c2 == '_');
            }
            sb.append(c2);
            i++;
        }
        kn.k(i - kn.b);
        return sb.toString();
    }
}

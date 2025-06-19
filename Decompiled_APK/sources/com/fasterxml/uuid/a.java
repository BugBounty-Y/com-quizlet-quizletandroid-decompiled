package com.fasterxml.uuid;

import java.io.Serializable;
import java.security.SecureRandom;

/* loaded from: classes.dex */
public final class a implements Serializable, Cloneable, Comparable {
    public static final char[] c = "0123456789abcdefABCDEF".toCharArray();
    public static SecureRandom d;
    public final long a;
    public volatile String b;

    public a(byte[] bArr) {
        if (bArr.length != 6) {
            throw new NumberFormatException("Ethernet address has to consist of 6 bytes");
        }
        long j = bArr[0] & 255;
        for (int i = 1; i < 6; i++) {
            j = (j << 8) | (bArr[i] & 255);
        }
        this.a = j;
    }

    public static void b(StringBuilder sb, int i) {
        char[] cArr = c;
        sb.append(cArr[(i >> 4) & 15]);
        sb.append(cArr[i & 15]);
    }

    public final Object clone() {
        return new a(this.a);
    }

    @Override // java.lang.Comparable
    public final int compareTo(Object obj) {
        long j = this.a - ((a) obj).a;
        if (j < 0) {
            return -1;
        }
        return j == 0 ? 0 : 1;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        return obj != null && obj.getClass() == a.class && ((a) obj).a == this.a;
    }

    public final int hashCode() {
        long j = this.a;
        return ((int) (j >>> 32)) ^ ((int) j);
    }

    public final String toString() {
        String str = this.b;
        if (str != null) {
            return str;
        }
        StringBuilder sb = new StringBuilder(17);
        long j = this.a;
        int i = (int) (j >> 32);
        int i2 = (int) j;
        b(sb, i >> 8);
        sb.append(':');
        b(sb, i);
        sb.append(':');
        b(sb, i2 >> 24);
        sb.append(':');
        b(sb, i2 >> 16);
        sb.append(':');
        b(sb, i2 >> 8);
        sb.append(':');
        b(sb, i2);
        String string = sb.toString();
        this.b = string;
        return string;
    }

    public a(long j) {
        this.a = j;
    }
}

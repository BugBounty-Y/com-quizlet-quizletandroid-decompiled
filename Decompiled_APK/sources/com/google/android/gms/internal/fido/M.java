package com.google.android.gms.internal.fido;

import java.io.IOException;
import java.math.RoundingMode;
import java.util.Objects;

/* loaded from: classes2.dex */
public class M {
    public static final K d;
    public final J a;
    public final Character b;
    public volatile M c;

    static {
        new L("base64()", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");
        new L("base64Url()", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_");
        new M("base32()", "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567");
        new M("base32Hex()", "0123456789ABCDEFGHIJKLMNOPQRSTUV");
        d = new K(new J("base16()", "0123456789ABCDEF".toCharArray()));
    }

    public M(J j, Character ch) {
        this.a = j;
        if (ch != null) {
            byte[] bArr = j.g;
            if (bArr.length > 61 && bArr[61] != -1) {
                throw new IllegalArgumentException(AbstractC2937a.d("Padding character %s was already in alphabet", ch));
            }
        }
        this.b = ch;
    }

    public void a(StringBuilder sb, byte[] bArr, int i) {
        int i2 = 0;
        AbstractC2937a.n(0, i, bArr.length);
        while (i2 < i) {
            J j = this.a;
            b(i2, Math.min(j.f, i - i2), sb, bArr);
            i2 += j.f;
        }
    }

    public final void b(int i, int i2, StringBuilder sb, byte[] bArr) {
        int i3;
        AbstractC2937a.n(i, i + i2, bArr.length);
        J j = this.a;
        if (i2 > j.f) {
            throw new IllegalArgumentException();
        }
        int i4 = 0;
        long j2 = 0;
        for (int i5 = 0; i5 < i2; i5++) {
            j2 = (j2 | (bArr[i + i5] & 255)) << 8;
        }
        int i6 = (i2 + 1) * 8;
        while (true) {
            int i7 = i2 * 8;
            i3 = j.d;
            if (i4 >= i7) {
                break;
            }
            sb.append(j.b[((int) (j2 >>> ((i6 - i3) - i4))) & j.c]);
            i4 += i3;
        }
        if (this.b != null) {
            while (i4 < j.f * 8) {
                sb.append('=');
                i4 += i3;
            }
        }
    }

    public final String c(int i, byte[] bArr) {
        AbstractC2937a.n(0, i, bArr.length);
        J j = this.a;
        int i2 = j.f;
        RoundingMode roundingMode = RoundingMode.CEILING;
        StringBuilder sb = new StringBuilder(j.e * AbstractC2937a.a(i, i2));
        try {
            a(sb, bArr, i);
            return sb.toString();
        } catch (IOException e) {
            throw new AssertionError(e);
        }
    }

    public final boolean equals(Object obj) {
        if (obj instanceof M) {
            M m = (M) obj;
            if (this.a.equals(m.a) && Objects.equals(this.b, m.b)) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        return this.a.hashCode() ^ Objects.hashCode(this.b);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("BaseEncoding.");
        J j = this.a;
        sb.append(j);
        if (8 % j.d != 0) {
            Character ch = this.b;
            if (ch == null) {
                sb.append(".omitPadding()");
            } else {
                sb.append(".withPadChar('");
                sb.append(ch);
                sb.append("')");
            }
        }
        return sb.toString();
    }

    public M(String str, String str2) {
        this(new J(str, str2.toCharArray()), (Character) '=');
    }
}

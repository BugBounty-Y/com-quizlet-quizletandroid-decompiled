package com.google.android.gms.internal.ads;

import java.io.IOException;
import java.math.RoundingMode;
import java.util.Arrays;
import java.util.Objects;

/* loaded from: classes2.dex */
public class Tu {
    public static final Ru d;
    public final Qu a;
    public final Character b;
    public volatile Tu c;

    static {
        new Su("base64()", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");
        new Su("base64Url()", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_");
        new Tu("base32()", "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567");
        new Tu("base32Hex()", "0123456789ABCDEFGHIJKLMNOPQRSTUV");
        d = new Ru(new Qu("base16()", "0123456789ABCDEF".toCharArray()));
    }

    public Tu(Qu qu, Character ch) {
        this.a = qu;
        boolean z = true;
        if (ch != null) {
            byte[] bArr = qu.g;
            if (bArr.length > 61 && bArr[61] != -1) {
                z = false;
            }
        }
        if (!z) {
            throw new IllegalArgumentException(AbstractC2025es.r("Padding character %s was already in alphabet", ch));
        }
        this.b = ch;
    }

    public int a(byte[] bArr, CharSequence charSequence) throws zzgan {
        int i;
        CharSequence charSequenceE = e(charSequence);
        int length = charSequenceE.length();
        Qu qu = this.a;
        boolean[] zArr = qu.h;
        int i2 = qu.e;
        if (!zArr[length % i2]) {
            throw new zzgan(android.support.v4.media.session.a.f(charSequenceE.length(), "Invalid input length "));
        }
        int i3 = 0;
        for (int i4 = 0; i4 < charSequenceE.length(); i4 += i2) {
            long jA = 0;
            int i5 = 0;
            int i6 = 0;
            while (true) {
                i = qu.d;
                if (i5 >= i2) {
                    break;
                }
                jA <<= i;
                if (i4 + i5 < charSequenceE.length()) {
                    jA |= qu.a(charSequenceE.charAt(i6 + i4));
                    i6++;
                }
                i5++;
            }
            int i7 = i6 * i;
            int i8 = qu.f;
            int i9 = (i8 - 1) * 8;
            while (i9 >= (i8 * 8) - i7) {
                bArr[i3] = (byte) ((jA >>> i9) & 255);
                i9 -= 8;
                i3++;
            }
        }
        return i3;
    }

    public Tu b(Qu qu, Character ch) {
        return new Tu(qu, ch);
    }

    public void c(StringBuilder sb, byte[] bArr, int i) {
        int i2 = 0;
        AbstractC1981ds.K(0, i, bArr.length);
        while (i2 < i) {
            int i3 = this.a.f;
            f(i2, Math.min(i3, i - i2), sb, bArr);
            i2 += i3;
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r4v12 */
    public final Tu d() {
        Qu qu;
        boolean z;
        Tu tuB = this.c;
        if (tuB == null) {
            Qu qu2 = this.a;
            int i = 0;
            while (true) {
                char[] cArr = qu2.b;
                int length = cArr.length;
                if (i >= length) {
                    qu = qu2;
                    break;
                }
                if (AbstractC2543qs.y(cArr[i])) {
                    int i2 = 0;
                    while (true) {
                        if (i2 >= length) {
                            z = false;
                            break;
                        }
                        char c = cArr[i2];
                        if (c >= 'a' && c <= 'z') {
                            z = true;
                            break;
                        }
                        i2++;
                    }
                    AbstractC1981ds.L("Cannot call lowerCase() on a mixed-case alphabet", !z);
                    char[] cArr2 = new char[cArr.length];
                    for (int i3 = 0; i3 < cArr.length; i3++) {
                        char c2 = cArr[i3];
                        if (AbstractC2543qs.y(c2)) {
                            c2 ^= 32;
                        }
                        cArr2[i3] = (char) c2;
                    }
                    qu = new Qu(qu2.a.concat(".lowerCase()"), cArr2);
                    if (qu2.i && !qu.i) {
                        byte[] bArr = qu.g;
                        byte[] bArrCopyOf = Arrays.copyOf(bArr, bArr.length);
                        for (int i4 = 65; i4 <= 90; i4++) {
                            int i5 = i4 | 32;
                            byte b = bArr[i4];
                            byte b2 = bArr[i5];
                            if (b == -1) {
                                bArrCopyOf[i4] = b2;
                            } else {
                                char c3 = (char) i4;
                                char c4 = (char) i5;
                                if (b2 != -1) {
                                    throw new IllegalStateException(AbstractC2025es.r("Can't ignoreCase() since '%s' and '%s' encode different values", Character.valueOf(c3), Character.valueOf(c4)));
                                }
                                bArrCopyOf[i5] = b;
                            }
                        }
                        qu = new Qu(qu.a.concat(".ignoreCase()"), qu.b, bArrCopyOf, true);
                    }
                } else {
                    i++;
                }
            }
            tuB = qu == qu2 ? this : b(qu, this.b);
            this.c = tuB;
        }
        return tuB;
    }

    public final CharSequence e(CharSequence charSequence) {
        if (this.b == null) {
            return charSequence;
        }
        int length = charSequence.length();
        do {
            length--;
            if (length < 0) {
                break;
            }
        } while (charSequence.charAt(length) == '=');
        return charSequence.subSequence(0, length + 1);
    }

    public final boolean equals(Object obj) {
        if (obj instanceof Tu) {
            Tu tu = (Tu) obj;
            if (this.a.equals(tu.a) && Objects.equals(this.b, tu.b)) {
                return true;
            }
        }
        return false;
    }

    public final void f(int i, int i2, StringBuilder sb, byte[] bArr) {
        int i3;
        AbstractC1981ds.K(i, i + i2, bArr.length);
        Qu qu = this.a;
        int i4 = qu.f;
        int i5 = 0;
        AbstractC1981ds.C(i2 <= i4);
        long j = 0;
        for (int i6 = 0; i6 < i2; i6++) {
            j = (j | (bArr[i + i6] & 255)) << 8;
        }
        int i7 = (i2 + 1) * 8;
        while (true) {
            int i8 = i2 * 8;
            i3 = qu.d;
            if (i5 >= i8) {
                break;
            }
            sb.append(qu.b[qu.c & ((int) (j >>> ((i7 - i3) - i5)))]);
            i5 += i3;
        }
        if (this.b != null) {
            while (i5 < i4 * 8) {
                sb.append('=');
                i5 += i3;
            }
        }
    }

    public final String g(int i, byte[] bArr) {
        AbstractC1981ds.K(0, i, bArr.length);
        Qu qu = this.a;
        int i2 = qu.f;
        RoundingMode roundingMode = RoundingMode.CEILING;
        StringBuilder sb = new StringBuilder(qu.e * AbstractC2025es.n(i, i2));
        try {
            c(sb, bArr, i);
            return sb.toString();
        } catch (IOException e) {
            throw new AssertionError(e);
        }
    }

    public final byte[] h(String str) {
        try {
            int length = (int) (((this.a.d * r6.length()) + 7) / 8);
            byte[] bArr = new byte[length];
            int iA = a(bArr, e(str));
            if (iA == length) {
                return bArr;
            }
            byte[] bArr2 = new byte[iA];
            System.arraycopy(bArr, 0, bArr2, 0, iA);
            return bArr2;
        } catch (zzgan e) {
            throw new IllegalArgumentException(e);
        }
    }

    public final int hashCode() {
        return this.a.hashCode() ^ Objects.hashCode(this.b);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("BaseEncoding.");
        Qu qu = this.a;
        sb.append(qu);
        if (8 % qu.d != 0) {
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

    public Tu(String str, String str2) {
        this(new Qu(str, str2.toCharArray()), (Character) '=');
    }
}

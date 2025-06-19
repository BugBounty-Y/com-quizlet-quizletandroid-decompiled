package com.google.android.gms.internal.fido;

import java.util.Arrays;

/* loaded from: classes2.dex */
public final class X extends b0 {
    public final T a;

    public X(T t) {
        this.a = t;
    }

    @Override // com.google.android.gms.internal.fido.b0
    public final int a() {
        return b0.d((byte) 64);
    }

    @Override // java.lang.Comparable
    public final int compareTo(Object obj) {
        b0 b0Var = (b0) obj;
        int iA = b0Var.a();
        int iD = b0.d((byte) 64);
        if (iD != iA) {
            return iD - b0Var.a();
        }
        T t = this.a;
        byte[] bArr = t.b;
        int length = bArr.length;
        T t2 = ((X) b0Var).a;
        byte[] bArr2 = t2.b;
        if (length != bArr2.length) {
            return bArr.length - bArr2.length;
        }
        return P.a.compare(t.m(), t2.m());
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj != null && X.class == obj.getClass()) {
            return this.a.equals(((X) obj).a);
        }
        return false;
    }

    public final int hashCode() {
        return Arrays.hashCode(new Object[]{Integer.valueOf(b0.d((byte) 64)), this.a});
    }

    /* JADX WARN: Multi-variable type inference failed */
    public final String toString() {
        J j;
        int i;
        boolean z;
        K k = M.d;
        M k2 = k.c;
        if (k2 == null) {
            J j2 = k.a;
            int i2 = 0;
            while (true) {
                char[] cArr = j2.b;
                if (i2 >= cArr.length) {
                    j = j2;
                    break;
                }
                char c = cArr[i2];
                if (c < 'a' || c > 'z') {
                    i2++;
                } else {
                    int i3 = 0;
                    while (true) {
                        if (i3 >= cArr.length) {
                            z = false;
                            break;
                        }
                        char c2 = cArr[i3];
                        if (c2 >= 'A' && c2 <= 'Z') {
                            z = true;
                            break;
                        }
                        i3++;
                    }
                    if (z) {
                        throw new IllegalStateException("Cannot call upperCase() on a mixed-case alphabet");
                    }
                    char[] cArr2 = new char[cArr.length];
                    for (int i4 = 0; i4 < cArr.length; i4++) {
                        char c3 = cArr[i4];
                        if (c3 >= 97 && c3 <= 122) {
                            c3 ^= 32;
                        }
                        cArr2[i4] = (char) c3;
                    }
                    j = new J(j2.a.concat(".upperCase()"), cArr2);
                    if (j2.h && !j.h) {
                        byte[] bArr = j.g;
                        byte[] bArrCopyOf = Arrays.copyOf(bArr, bArr.length);
                        for (i = 65; i <= 90; i++) {
                            int i5 = i | 32;
                            byte b = bArr[i];
                            byte b2 = bArr[i5];
                            if (b == -1) {
                                bArrCopyOf[i] = b2;
                            } else {
                                char c4 = (char) i;
                                char c5 = (char) i5;
                                if (b2 != -1) {
                                    throw new IllegalStateException(AbstractC2937a.d("Can't ignoreCase() since '%s' and '%s' encode different values", Character.valueOf(c4), Character.valueOf(c5)));
                                }
                                bArrCopyOf[i5] = b;
                            }
                        }
                        j = new J(j.a.concat(".ignoreCase()"), j.b, bArrCopyOf, true);
                    }
                }
            }
            k2 = j == j2 ? k : new K(j);
            k.c = k2;
        }
        byte[] bArrM = this.a.m();
        return android.support.v4.media.session.a.B("h'", k2.c(bArrM.length, bArrM), "'");
    }
}

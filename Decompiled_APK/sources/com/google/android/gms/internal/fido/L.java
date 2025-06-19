package com.google.android.gms.internal.fido;

/* loaded from: classes2.dex */
public final class L extends M {
    /* JADX WARN: Illegal instructions before constructor call */
    public L(String str, String str2) {
        char[] charArray = str2.toCharArray();
        super(new J(str, charArray), (Character) '=');
        if (charArray.length != 64) {
            throw new IllegalArgumentException();
        }
    }

    @Override // com.google.android.gms.internal.fido.M
    public final void a(StringBuilder sb, byte[] bArr, int i) {
        int i2 = 0;
        AbstractC2937a.n(0, i, bArr.length);
        for (int i3 = i; i3 >= 3; i3 -= 3) {
            int i4 = ((bArr[i2 + 1] & 255) << 8) | ((bArr[i2] & 255) << 16) | (bArr[i2 + 2] & 255);
            J j = this.a;
            sb.append(j.b[i4 >>> 18]);
            char[] cArr = j.b;
            sb.append(cArr[(i4 >>> 12) & 63]);
            sb.append(cArr[(i4 >>> 6) & 63]);
            sb.append(cArr[i4 & 63]);
            i2 += 3;
        }
        if (i2 < i) {
            b(i2, i - i2, sb, bArr);
        }
    }
}

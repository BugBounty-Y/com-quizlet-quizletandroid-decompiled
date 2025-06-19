package com.google.android.gms.internal.fido;

/* loaded from: classes2.dex */
public final class K extends M {
    public final char[] e;

    public K(J j) {
        super(j, (Character) null);
        this.e = new char[com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH];
        char[] cArr = j.b;
        if (cArr.length != 16) {
            throw new IllegalArgumentException();
        }
        for (int i = 0; i < 256; i++) {
            char[] cArr2 = this.e;
            cArr2[i] = cArr[i >>> 4];
            cArr2[i | 256] = cArr[i & 15];
        }
    }

    @Override // com.google.android.gms.internal.fido.M
    public final void a(StringBuilder sb, byte[] bArr, int i) {
        AbstractC2937a.n(0, i, bArr.length);
        for (int i2 = 0; i2 < i; i2++) {
            int i3 = bArr[i2] & 255;
            char[] cArr = this.e;
            sb.append(cArr[i3]);
            sb.append(cArr[i3 | 256]);
        }
    }
}

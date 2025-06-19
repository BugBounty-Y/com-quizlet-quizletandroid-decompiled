package com.google.android.gms.internal.ads;

/* loaded from: classes2.dex */
public final class Ru extends Tu {
    public final char[] e;

    public Ru(Qu qu) {
        super(qu, (Character) null);
        this.e = new char[com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH];
        char[] cArr = qu.b;
        AbstractC1981ds.C(cArr.length == 16);
        for (int i = 0; i < 256; i++) {
            char[] cArr2 = this.e;
            cArr2[i] = cArr[i >>> 4];
            cArr2[i | 256] = cArr[i & 15];
        }
    }

    @Override // com.google.android.gms.internal.ads.Tu
    public final int a(byte[] bArr, CharSequence charSequence) throws zzgan {
        if (charSequence.length() % 2 == 1) {
            throw new zzgan(android.support.v4.media.session.a.f(charSequence.length(), "Invalid input length "));
        }
        int i = 0;
        int i2 = 0;
        while (i < charSequence.length()) {
            char cCharAt = charSequence.charAt(i);
            Qu qu = this.a;
            bArr[i2] = (byte) ((qu.a(cCharAt) << 4) | qu.a(charSequence.charAt(i + 1)));
            i += 2;
            i2++;
        }
        return i2;
    }

    @Override // com.google.android.gms.internal.ads.Tu
    public final Tu b(Qu qu, Character ch) {
        return new Ru(qu);
    }

    @Override // com.google.android.gms.internal.ads.Tu
    public final void c(StringBuilder sb, byte[] bArr, int i) {
        AbstractC1981ds.K(0, i, bArr.length);
        for (int i2 = 0; i2 < i; i2++) {
            int i3 = bArr[i2] & 255;
            char[] cArr = this.e;
            sb.append(cArr[i3]);
            sb.append(cArr[i3 | 256]);
        }
    }
}

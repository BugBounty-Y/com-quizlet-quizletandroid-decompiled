package com.google.android.gms.internal.ads;

/* loaded from: classes2.dex */
public final class Su extends Tu {
    public Su(Qu qu, Character ch) {
        super(qu, ch);
        AbstractC1981ds.C(qu.b.length == 64);
    }

    @Override // com.google.android.gms.internal.ads.Tu
    public final int a(byte[] bArr, CharSequence charSequence) throws zzgan {
        CharSequence charSequenceE = e(charSequence);
        int length = charSequenceE.length();
        Qu qu = this.a;
        if (!qu.h[length % qu.e]) {
            throw new zzgan(android.support.v4.media.session.a.f(charSequenceE.length(), "Invalid input length "));
        }
        int i = 0;
        int i2 = 0;
        while (i < charSequenceE.length()) {
            int i3 = i2 + 1;
            int iA = (qu.a(charSequenceE.charAt(i + 1)) << 12) | (qu.a(charSequenceE.charAt(i)) << 18);
            bArr[i2] = (byte) (iA >>> 16);
            int i4 = i + 2;
            if (i4 < charSequenceE.length()) {
                int i5 = i + 3;
                int iA2 = iA | (qu.a(charSequenceE.charAt(i4)) << 6);
                int i6 = i2 + 2;
                bArr[i3] = (byte) ((iA2 >>> 8) & 255);
                if (i5 < charSequenceE.length()) {
                    i += 4;
                    i2 += 3;
                    bArr[i6] = (byte) ((iA2 | qu.a(charSequenceE.charAt(i5))) & 255);
                } else {
                    i2 = i6;
                    i = i5;
                }
            } else {
                i = i4;
                i2 = i3;
            }
        }
        return i2;
    }

    @Override // com.google.android.gms.internal.ads.Tu
    public final Tu b(Qu qu, Character ch) {
        return new Su(qu, ch);
    }

    @Override // com.google.android.gms.internal.ads.Tu
    public final void c(StringBuilder sb, byte[] bArr, int i) {
        int i2 = 0;
        AbstractC1981ds.K(0, i, bArr.length);
        for (int i3 = i; i3 >= 3; i3 -= 3) {
            int i4 = ((bArr[i2 + 1] & 255) << 8) | ((bArr[i2] & 255) << 16) | (bArr[i2 + 2] & 255);
            Qu qu = this.a;
            sb.append(qu.b[i4 >>> 18]);
            char[] cArr = qu.b;
            sb.append(cArr[(i4 >>> 12) & 63]);
            sb.append(cArr[(i4 >>> 6) & 63]);
            sb.append(cArr[i4 & 63]);
            i2 += 3;
        }
        if (i2 < i) {
            f(i2, i - i2, sb, bArr);
        }
    }

    public Su(String str, String str2) {
        this(new Qu(str, str2.toCharArray()), (Character) '=');
    }
}

package com.google.android.gms.internal.ads;

import android.text.SpannableStringBuilder;
import android.text.style.ForegroundColorSpan;
import android.text.style.StyleSpan;
import android.text.style.TypefaceSpan;
import android.text.style.UnderlineSpan;
import androidx.camera.core.impl.C0186z;
import com.skydoves.balloon.internals.DefinitionKt;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.List;

/* renamed from: com.google.android.gms.internal.ads.w2, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2768w2 implements InterfaceC1818a2 {
    public final Kn a = new Kn();
    public final boolean b;
    public final int c;
    public final int d;
    public final String e;
    public final float f;
    public final int g;

    public C2768w2(List list) {
        if (list.size() != 1 || (((byte[]) list.get(0)).length != 48 && ((byte[]) list.get(0)).length != 53)) {
            this.c = 0;
            this.d = -1;
            this.e = "sans-serif";
            this.b = false;
            this.f = 0.85f;
            this.g = -1;
            return;
        }
        byte[] bArr = (byte[]) list.get(0);
        this.c = bArr[24];
        this.d = ((bArr[26] & 255) << 24) | ((bArr[27] & 255) << 16) | ((bArr[28] & 255) << 8) | (bArr[29] & 255);
        this.e = true == "Serif".equals(new String(bArr, 43, bArr.length + (-43), StandardCharsets.UTF_8)) ? "serif" : "sans-serif";
        int i = bArr[25] * 20;
        this.g = i;
        boolean z = (bArr[0] & 32) != 0;
        this.b = z;
        if (z) {
            this.f = Math.max(DefinitionKt.NO_Float_VALUE, Math.min(((bArr[11] & 255) | ((bArr[10] & 255) << 8)) / i, 0.95f));
        } else {
            this.f = 0.85f;
        }
    }

    public static void b(SpannableStringBuilder spannableStringBuilder, int i, int i2, int i3, int i4, int i5) {
        if (i != i2) {
            spannableStringBuilder.setSpan(new ForegroundColorSpan((i >>> 8) | ((i & 255) << 24)), i3, i4, i5 | 33);
        }
    }

    public static void c(SpannableStringBuilder spannableStringBuilder, int i, int i2, int i3, int i4, int i5) {
        if (i != i2) {
            int i6 = i5 | 33;
            int i7 = i & 1;
            int i8 = i & 2;
            boolean z = true;
            if (i7 != 0) {
                if (i8 != 0) {
                    spannableStringBuilder.setSpan(new StyleSpan(3), i3, i4, i6);
                } else {
                    spannableStringBuilder.setSpan(new StyleSpan(1), i3, i4, i6);
                    z = false;
                }
            } else if (i8 != 0) {
                spannableStringBuilder.setSpan(new StyleSpan(2), i3, i4, i6);
            } else {
                z = false;
            }
            if ((i & 4) != 0) {
                spannableStringBuilder.setSpan(new UnderlineSpan(), i3, i4, i6);
            } else {
                if (i7 != 0 || z) {
                    return;
                }
                spannableStringBuilder.setSpan(new StyleSpan(0), i3, i4, i6);
            }
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // com.google.android.gms.internal.ads.InterfaceC1818a2
    public final void a(byte[] bArr, int i, int i2, C0186z c0186z) {
        String strB;
        int i3;
        int i4;
        int i5;
        int i6;
        int i7;
        int i8;
        int i9;
        int i10;
        int i11;
        Kn kn = this.a;
        kn.h(i + i2, bArr);
        kn.j(i);
        int i12 = 0;
        int i13 = 1;
        int i14 = 2;
        AbstractC1795We.B(kn.s() >= 2);
        int iD = kn.D();
        if (iD == 0) {
            strB = "";
        } else {
            int i15 = kn.b;
            Charset charsetC = kn.c();
            int i16 = kn.b - i15;
            if (charsetC == null) {
                charsetC = StandardCharsets.UTF_8;
            }
            strB = kn.b(iD - i16, charsetC);
        }
        if (strB.isEmpty()) {
            C2244ju c2244ju = AbstractC2330lu.b;
            c0186z.mo10b(new X1(Bu.e, -9223372036854775807L, -9223372036854775807L));
            return;
        }
        SpannableStringBuilder spannableStringBuilder = new SpannableStringBuilder(strB);
        int length = spannableStringBuilder.length();
        int i17 = this.c;
        c(spannableStringBuilder, i17, 0, 0, length, 16711680);
        int i18 = i17;
        int length2 = spannableStringBuilder.length();
        int i19 = this.d;
        b(spannableStringBuilder, i19, -1, 0, length2, 16711680);
        int i20 = i19;
        int length3 = spannableStringBuilder.length();
        String str = this.e;
        if (str != "sans-serif") {
            spannableStringBuilder.setSpan(new TypefaceSpan(str), 0, length3, 16711713);
        }
        float fMax = this.f;
        while (kn.s() >= 8) {
            int i21 = kn.b;
            int iU = kn.u();
            int iU2 = kn.u();
            if (iU2 == 1937013100) {
                AbstractC1795We.B(kn.s() >= i14 ? i13 : i12);
                int iD2 = kn.D();
                int i22 = i12;
                while (i22 < iD2) {
                    AbstractC1795We.B(kn.s() >= 12 ? i13 : i12);
                    int iD3 = kn.D();
                    int iD4 = kn.D();
                    kn.k(i14);
                    int i23 = iD2;
                    int iZ = kn.z();
                    kn.k(i13);
                    int iU3 = kn.u();
                    int i24 = i13;
                    if (iD4 > spannableStringBuilder.length()) {
                        i7 = i18;
                        i8 = i20;
                        AbstractC2096gb.J("Tx3gParser", android.support.v4.media.session.a.j("Truncating styl end (", iD4, ") to cueText.length() (", ").", spannableStringBuilder.length()));
                        iD4 = spannableStringBuilder.length();
                    } else {
                        i7 = i18;
                        i8 = i20;
                    }
                    if (iD3 >= iD4) {
                        AbstractC2096gb.J("Tx3gParser", android.support.v4.media.session.a.j("Ignoring styl with start (", iD3, ") >= end (", ").", iD4));
                        i10 = i22;
                        i9 = i23;
                        i11 = i8;
                    } else {
                        i9 = i23;
                        i10 = i22;
                        c(spannableStringBuilder, iZ, i7, iD3, iD4, 0);
                        i11 = i8;
                        b(spannableStringBuilder, iU3, i11, iD3, iD4, 0);
                    }
                    i13 = i24;
                    iD2 = i9;
                    i20 = i11;
                    i18 = i7;
                    i14 = 2;
                    i22 = i10 + 1;
                    i12 = 0;
                }
                i3 = i18;
                i4 = i13;
                i5 = i20;
                i6 = i14;
            } else {
                i3 = i18;
                i4 = i13;
                i5 = i20;
                if (iU2 == 1952608120 && this.b) {
                    i6 = 2;
                    AbstractC1795We.B(kn.s() >= 2 ? i4 : 0);
                    float fD = kn.D();
                    String str2 = Yo.a;
                    fMax = Math.max(DefinitionKt.NO_Float_VALUE, Math.min(fD / this.g, 0.95f));
                } else {
                    i6 = 2;
                }
            }
            kn.j(i21 + iU);
            i13 = i4;
            i14 = i6;
            i20 = i5;
            i18 = i3;
            i12 = 0;
        }
        c0186z.mo10b(new X1(AbstractC2330lu.s(new Gg(spannableStringBuilder, null, null, null, fMax, 0, 0, -3.4028235E38f, Integer.MIN_VALUE, Integer.MIN_VALUE, -3.4028235E38f, -3.4028235E38f, -3.4028235E38f, Integer.MIN_VALUE, DefinitionKt.NO_Float_VALUE)), -9223372036854775807L, -9223372036854775807L));
    }
}

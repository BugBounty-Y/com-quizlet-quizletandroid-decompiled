package com.google.android.gms.internal.ads;

import androidx.core.view.AbstractC1047f0;
import java.nio.charset.Charset;

/* renamed from: com.google.android.gms.internal.ads.zA, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public class C2905zA extends BA {
    public final byte[] c;

    public C2905zA(byte[] bArr) {
        bArr.getClass();
        this.c = bArr;
    }

    public final boolean A(C2905zA c2905zA, int i, int i2) {
        if (i2 > c2905zA.g()) {
            throw new IllegalArgumentException("Length too large: " + i2 + g());
        }
        if (i + i2 > c2905zA.g()) {
            int iG = c2905zA.g();
            StringBuilder sbW = android.support.v4.media.session.a.w("Ran off end of other: ", i, ", ", ", ", i2);
            sbW.append(iG);
            throw new IllegalArgumentException(sbW.toString());
        }
        int iZ = z() + i2;
        int iZ2 = z();
        int iZ3 = c2905zA.z() + i;
        while (iZ2 < iZ) {
            if (this.c[iZ2] != c2905zA.c[iZ3]) {
                return false;
            }
            iZ2++;
            iZ3++;
        }
        return true;
    }

    @Override // com.google.android.gms.internal.ads.BA
    public byte b(int i) {
        return this.c[i];
    }

    @Override // com.google.android.gms.internal.ads.BA
    public byte c(int i) {
        return this.c[i];
    }

    @Override // com.google.android.gms.internal.ads.BA
    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if ((obj instanceof BA) && g() == ((BA) obj).g()) {
            if (g() == 0) {
                return true;
            }
            if (!(obj instanceof C2905zA)) {
                return obj.equals(this);
            }
            C2905zA c2905zA = (C2905zA) obj;
            int i = this.a;
            int i2 = c2905zA.a;
            if (i == 0 || i2 == 0 || i == i2) {
                return A(c2905zA, 0, g());
            }
        }
        return false;
    }

    @Override // com.google.android.gms.internal.ads.BA
    public int g() {
        return this.c.length;
    }

    @Override // com.google.android.gms.internal.ads.BA
    public void h(int i, int i2, byte[] bArr, int i3) {
        System.arraycopy(this.c, i, bArr, i2, i3);
    }

    @Override // com.google.android.gms.internal.ads.BA
    public final int j() {
        return 0;
    }

    @Override // com.google.android.gms.internal.ads.BA
    public final boolean k() {
        return true;
    }

    @Override // com.google.android.gms.internal.ads.BA
    public final int m(int i, int i2, int i3) {
        int iZ = z() + i2;
        Charset charset = WA.a;
        for (int i4 = iZ; i4 < iZ + i3; i4++) {
            i = (i * 31) + this.c[i4];
        }
        return i;
    }

    @Override // com.google.android.gms.internal.ads.BA
    public final BA n(int i, int i2) {
        int iT = BA.t(i, i2, g());
        return iT == 0 ? BA.b : new C2862yA(z() + i, this.c, iT);
    }

    @Override // com.google.android.gms.internal.ads.BA
    public final AbstractC1047f0 o() {
        return AbstractC1047f0.K(z(), this.c, g());
    }

    @Override // com.google.android.gms.internal.ads.BA
    public final void s(HA ha) {
        ha.h(z(), this.c, g());
    }

    public int z() {
        return 0;
    }
}

package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;
import java.util.Objects;

/* loaded from: classes2.dex */
public final class Hw extends AbstractC2804ww {
    public final int a;
    public final int b;
    public final int c;
    public final int d;
    public final Gw e;
    public final Ew f;

    public Hw(int i, int i2, int i3, int i4, Gw gw, Ew ew) {
        this.a = i;
        this.b = i2;
        this.c = i3;
        this.d = i4;
        this.e = gw;
        this.f = ew;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2547qw
    public final boolean a() {
        return this.e != Gw.e;
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof Hw)) {
            return false;
        }
        Hw hw = (Hw) obj;
        return hw.a == this.a && hw.b == this.b && hw.c == this.c && hw.d == this.d && hw.e == this.e && hw.f == this.f;
    }

    public final int hashCode() {
        return Objects.hash(Hw.class, Integer.valueOf(this.a), Integer.valueOf(this.b), Integer.valueOf(this.c), Integer.valueOf(this.d), this.e, this.f);
    }

    public final String toString() {
        StringBuilder sbH = AbstractC0147y.h("AesCtrHmacAead Parameters (variant: ", String.valueOf(this.e), ", hashType: ", String.valueOf(this.f), ", ");
        sbH.append(this.c);
        sbH.append("-byte IV, and ");
        sbH.append(this.d);
        sbH.append("-byte tags, and ");
        sbH.append(this.a);
        sbH.append("-byte AES key, and ");
        return android.support.v4.media.session.a.r(sbH, this.b, "-byte HMAC key)");
    }
}

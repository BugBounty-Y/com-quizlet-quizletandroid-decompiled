package com.google.android.gms.internal.ads;

import java.util.Objects;

/* loaded from: classes2.dex */
public final class Mw extends AbstractC2804ww {
    public final int a;
    public final int b;
    public final Lw c;

    public Mw(int i, int i2, Lw lw) {
        this.a = i;
        this.b = i2;
        this.c = lw;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2547qw
    public final boolean a() {
        return this.c != Lw.e;
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof Mw)) {
            return false;
        }
        Mw mw = (Mw) obj;
        return mw.a == this.a && mw.b == this.b && mw.c == this.c;
    }

    public final int hashCode() {
        return Objects.hash(Mw.class, Integer.valueOf(this.a), Integer.valueOf(this.b), 16, this.c);
    }

    public final String toString() {
        StringBuilder sbY = android.support.v4.media.session.a.y("AesEax Parameters (variant: ", String.valueOf(this.c), ", ");
        sbY.append(this.b);
        sbY.append("-byte IV, 16-byte tag, and ");
        return android.support.v4.media.session.a.r(sbY, this.a, "-byte key)");
    }
}

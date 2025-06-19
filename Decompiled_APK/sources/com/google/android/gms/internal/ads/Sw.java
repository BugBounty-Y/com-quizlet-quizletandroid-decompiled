package com.google.android.gms.internal.ads;

import java.util.Objects;

/* loaded from: classes2.dex */
public final class Sw extends AbstractC2804ww {
    public final int a;
    public final Ew b;

    public Sw(int i, Ew ew) {
        this.a = i;
        this.b = ew;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2547qw
    public final boolean a() {
        return this.b != Ew.j;
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof Sw)) {
            return false;
        }
        Sw sw = (Sw) obj;
        return sw.a == this.a && sw.b == this.b;
    }

    public final int hashCode() {
        return Objects.hash(Sw.class, Integer.valueOf(this.a), this.b);
    }

    public final String toString() {
        return android.support.v4.media.session.a.r(android.support.v4.media.session.a.y("AesGcmSiv Parameters (variant: ", String.valueOf(this.b), ", "), this.a, "-byte key)");
    }
}

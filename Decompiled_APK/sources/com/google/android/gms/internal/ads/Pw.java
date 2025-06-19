package com.google.android.gms.internal.ads;

import java.util.Objects;

/* loaded from: classes2.dex */
public final class Pw extends AbstractC2804ww {
    public final int a;
    public final C2332lw b;

    public Pw(int i, C2332lw c2332lw) {
        this.a = i;
        this.b = c2332lw;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2547qw
    public final boolean a() {
        return this.b != C2332lw.h;
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof Pw)) {
            return false;
        }
        Pw pw = (Pw) obj;
        return pw.a == this.a && pw.b == this.b;
    }

    public final int hashCode() {
        return Objects.hash(Pw.class, Integer.valueOf(this.a), 12, 16, this.b);
    }

    public final String toString() {
        return android.support.v4.media.session.a.r(android.support.v4.media.session.a.y("AesGcm Parameters (variant: ", String.valueOf(this.b), ", 12-byte IV, 16-byte tag, and "), this.a, "-byte key)");
    }
}

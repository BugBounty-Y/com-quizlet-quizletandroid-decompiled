package com.google.android.gms.internal.ads;

import java.util.Objects;

/* loaded from: classes2.dex */
public final class Vw extends AbstractC2804ww {
    public final Gw a;

    public Vw(Gw gw) {
        this.a = gw;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2547qw
    public final boolean a() {
        return this.a != Gw.h;
    }

    public final boolean equals(Object obj) {
        return (obj instanceof Vw) && ((Vw) obj).a == this.a;
    }

    public final int hashCode() {
        return Objects.hash(Vw.class, this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.B("ChaCha20Poly1305 Parameters (variant: ", this.a.b, ")");
    }
}

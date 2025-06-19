package com.google.android.gms.internal.ads;

import java.util.Objects;

/* renamed from: com.google.android.gms.internal.ads.jx, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2247jx extends AbstractC2804ww {
    public final Lw a;

    public C2247jx(Lw lw) {
        this.a = lw;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2547qw
    public final boolean a() {
        return this.a != Lw.j;
    }

    public final boolean equals(Object obj) {
        return (obj instanceof C2247jx) && ((C2247jx) obj).a == this.a;
    }

    public final int hashCode() {
        return Objects.hash(C2247jx.class, this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.B("XChaCha20Poly1305 Parameters (variant: ", this.a.b, ")");
    }
}

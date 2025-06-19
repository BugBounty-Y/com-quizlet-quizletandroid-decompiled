package com.google.android.gms.internal.ads;

import java.security.GeneralSecurityException;
import java.util.Objects;

/* renamed from: com.google.android.gms.internal.ads.gx, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2118gx extends AbstractC2804ww {
    public final Gw a;
    public final int b;

    public C2118gx(Gw gw, int i) {
        this.a = gw;
        this.b = i;
    }

    public static C2118gx b(Gw gw, int i) throws GeneralSecurityException {
        if (i < 8 || i > 12) {
            throw new GeneralSecurityException("Salt size must be between 8 and 12 bytes");
        }
        return new C2118gx(gw, i);
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2547qw
    public final boolean a() {
        return this.a != Gw.j;
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof C2118gx)) {
            return false;
        }
        C2118gx c2118gx = (C2118gx) obj;
        return c2118gx.a == this.a && c2118gx.b == this.b;
    }

    public final int hashCode() {
        return Objects.hash(C2118gx.class, this.a, Integer.valueOf(this.b));
    }

    public final String toString() {
        return android.support.v4.media.session.a.r(android.support.v4.media.session.a.y("X-AES-GCM Parameters (variant: ", this.a.b, "salt_size_bytes: "), this.b, ")");
    }
}

package com.google.android.gms.internal.ads;

import java.util.Objects;

/* loaded from: classes2.dex */
public final class Zw extends AbstractC2804ww {
    public final String a;
    public final Lw b;

    public Zw(String str, Lw lw) {
        this.a = str;
        this.b = lw;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2547qw
    public final boolean a() {
        return this.b != Lw.g;
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof Zw)) {
            return false;
        }
        Zw zw = (Zw) obj;
        return zw.a.equals(this.a) && zw.b.equals(this.b);
    }

    public final int hashCode() {
        return Objects.hash(Zw.class, this.a, this.b);
    }

    public final String toString() {
        return androidx.compose.ui.node.B.j(new StringBuilder("LegacyKmsAead Parameters (keyUri: "), this.a, ", variant: ", this.b.b, ")");
    }
}

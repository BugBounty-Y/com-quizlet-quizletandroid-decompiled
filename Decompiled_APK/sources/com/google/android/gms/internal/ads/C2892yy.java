package com.google.android.gms.internal.ads;

import java.util.Objects;

/* renamed from: com.google.android.gms.internal.ads.yy, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2892yy extends Hy {
    public final int a;
    public final int b;
    public final C2332lw c;

    public C2892yy(int i, int i2, C2332lw c2332lw) {
        this.a = i;
        this.b = i2;
        this.c = c2332lw;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2547qw
    public final boolean a() {
        return this.c != C2332lw.r;
    }

    public final int b() {
        C2332lw c2332lw = C2332lw.r;
        int i = this.b;
        C2332lw c2332lw2 = this.c;
        if (c2332lw2 == c2332lw) {
            return i;
        }
        if (c2332lw2 == C2332lw.o || c2332lw2 == C2332lw.p || c2332lw2 == C2332lw.q) {
            return i + 5;
        }
        throw new IllegalStateException("Unknown variant");
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof C2892yy)) {
            return false;
        }
        C2892yy c2892yy = (C2892yy) obj;
        return c2892yy.a == this.a && c2892yy.b() == b() && c2892yy.c == this.c;
    }

    public final int hashCode() {
        return Objects.hash(C2892yy.class, Integer.valueOf(this.a), Integer.valueOf(this.b), this.c);
    }

    public final String toString() {
        StringBuilder sbY = android.support.v4.media.session.a.y("AES-CMAC Parameters (variant: ", String.valueOf(this.c), ", ");
        sbY.append(this.b);
        sbY.append("-byte tags, and ");
        return android.support.v4.media.session.a.r(sbY, this.a, "-byte key)");
    }
}

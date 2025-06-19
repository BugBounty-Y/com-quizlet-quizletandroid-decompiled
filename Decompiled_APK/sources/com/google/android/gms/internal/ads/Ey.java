package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;
import java.util.Objects;

/* loaded from: classes2.dex */
public final class Ey extends Hy {
    public final int a;
    public final int b;
    public final Dy c;
    public final Cy d;

    public Ey(int i, int i2, Dy dy, Cy cy) {
        this.a = i;
        this.b = i2;
        this.c = dy;
        this.d = cy;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2547qw
    public final boolean a() {
        return this.c != Dy.e;
    }

    public final int b() {
        Dy dy = Dy.e;
        int i = this.b;
        Dy dy2 = this.c;
        if (dy2 == dy) {
            return i;
        }
        if (dy2 == Dy.b || dy2 == Dy.c || dy2 == Dy.d) {
            return i + 5;
        }
        throw new IllegalStateException("Unknown variant");
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof Ey)) {
            return false;
        }
        Ey ey = (Ey) obj;
        return ey.a == this.a && ey.b() == b() && ey.c == this.c && ey.d == this.d;
    }

    public final int hashCode() {
        return Objects.hash(Ey.class, Integer.valueOf(this.a), Integer.valueOf(this.b), this.c, this.d);
    }

    public final String toString() {
        StringBuilder sbH = AbstractC0147y.h("HMAC Parameters (variant: ", String.valueOf(this.c), ", hashType: ", String.valueOf(this.d), ", ");
        sbH.append(this.b);
        sbH.append("-byte tags, and ");
        return android.support.v4.media.session.a.r(sbH, this.a, "-byte key)");
    }
}

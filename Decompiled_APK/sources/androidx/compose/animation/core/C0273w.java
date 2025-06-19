package androidx.compose.animation.core;

/* renamed from: androidx.compose.animation.core.w, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0273w {
    public double a;
    public double b;

    public C0273w(double d, double d2) {
        this.a = d;
        this.b = d2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C0273w)) {
            return false;
        }
        C0273w c0273w = (C0273w) obj;
        return Double.compare(this.a, c0273w.a) == 0 && Double.compare(this.b, c0273w.b) == 0;
    }

    public final int hashCode() {
        return Double.hashCode(this.b) + (Double.hashCode(this.a) * 31);
    }

    public final String toString() {
        return "ComplexDouble(_real=" + this.a + ", _imaginary=" + this.b + ')';
    }
}

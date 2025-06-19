package androidx.constraintlayout.core.motion.utils;

/* loaded from: classes.dex */
public final class i extends e {
    public double e;
    public double f;

    @Override // androidx.constraintlayout.core.motion.utils.e
    public final double a(double d) {
        double d2 = this.f;
        double d3 = this.e;
        if (d < d2) {
            return (d2 * d) / (((d2 - d) * d3) + d);
        }
        return ((d - 1.0d) * (1.0d - d2)) / ((1.0d - d) - ((d2 - d) * d3));
    }

    @Override // androidx.constraintlayout.core.motion.utils.e
    public final double b(double d) {
        double d2 = this.f;
        double d3 = this.e;
        if (d < d2) {
            double d4 = d3 * d2 * d2;
            double d5 = ((d2 - d) * d3) + d;
            return d4 / (d5 * d5);
        }
        double d6 = d2 - 1.0d;
        double d7 = (((d2 - d) * (-d3)) - d) + 1.0d;
        return ((d6 * d3) * d6) / (d7 * d7);
    }
}

package androidx.compose.animation;

/* loaded from: classes.dex */
public final class f0 implements androidx.compose.animation.core.F {
    public final /* synthetic */ int a;
    public float b;
    public float c;

    public static f0 d(f0 f0Var, f0 f0Var2) {
        return new f0(f0Var.b - f0Var2.b, f0Var.c - f0Var2.c);
    }

    @Override // androidx.compose.animation.core.F
    public float a() {
        return this.b;
    }

    public e0 b(float f) {
        double dC = c(f);
        double d = g0.a;
        double d2 = d - 1.0d;
        return new e0(f, (float) (Math.exp((d / d2) * dC) * this.b * this.c), (long) (Math.exp(dC / d2) * 1000.0d));
    }

    public double c(float f) {
        float[] fArr = AbstractC0228b.a;
        return Math.log((Math.abs(f) * 0.35f) / (this.b * this.c));
    }

    @Override // androidx.compose.animation.core.F
    public float n(float f, float f2, long j) {
        float f3 = this.c;
        return ((f2 / f3) * ((float) Math.exp((f3 * (j / 1000000)) / 1000.0f))) + (f - (f2 / f3));
    }

    @Override // androidx.compose.animation.core.F
    public long q(float f) {
        return ((long) ((((float) Math.log(this.b / Math.abs(f))) * 1000.0f) / this.c)) * 1000000;
    }

    @Override // androidx.compose.animation.core.F
    public float r(float f, float f2) {
        if (Math.abs(f2) <= this.b) {
            return f;
        }
        double dLog = Math.log(Math.abs(r1 / f2));
        float f3 = this.c;
        return ((f2 / f3) * ((float) Math.exp((f3 * ((dLog / f3) * 1000)) / 1000.0f))) + (f - (f2 / f3));
    }

    public String toString() {
        switch (this.a) {
            case 5:
                return String.format("(%.4f, %.4f)", Float.valueOf(this.b), Float.valueOf(this.c));
            default:
                return super.toString();
        }
    }

    @Override // androidx.compose.animation.core.F
    public float v(long j, float f) {
        return f * ((float) Math.exp(((j / 1000000) / 1000.0f) * this.c));
    }

    public f0(float f, float f2) {
        this.a = 5;
        this.b = f;
        this.c = f2;
    }

    public f0(float f, androidx.compose.ui.unit.b bVar) {
        this.a = 0;
        this.b = f;
        float fA = bVar.a();
        float f2 = g0.a;
        this.c = fA * 386.0878f * 160.0f * 0.84f;
    }

    public f0() {
        this.a = 1;
        this.b = Math.max(1.0E-7f, Math.abs(0.1f));
        this.c = Math.max(1.0E-4f, 1.0f) * (-4.2f);
    }

    public f0(float f, float f2, float f3, float f4) {
        this.a = 2;
        this.b = f3;
        this.c = f4;
    }
}

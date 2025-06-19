package androidx.compose.animation.core;

import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes.dex */
public final class H implements E {
    public final int a;
    public final int b;
    public final B c;
    public final long d;
    public final long e;

    public H(int i, int i2, B b) {
        this.a = i;
        this.b = i2;
        this.c = b;
        this.d = i * 1000000;
        this.e = i2 * 1000000;
    }

    @Override // androidx.compose.animation.core.E
    public final float b(long j, float f, float f2, float f3) {
        long jD = kotlin.ranges.l.d(j - this.e, 0L, this.d);
        if (jD < 0) {
            return DefinitionKt.NO_Float_VALUE;
        }
        if (jD == 0) {
            return f3;
        }
        return (e(jD, f, f2, f3) - e(jD - 1000000, f, f2, f3)) * 1000.0f;
    }

    @Override // androidx.compose.animation.core.E
    public final long c(float f, float f2, float f3) {
        return (this.b + this.a) * 1000000;
    }

    @Override // androidx.compose.animation.core.E
    public final float e(long j, float f, float f2, float f3) {
        float fD = this.a == 0 ? 1.0f : kotlin.ranges.l.d(j - this.e, 0L, this.d) / this.d;
        if (fD < DefinitionKt.NO_Float_VALUE) {
            fD = 0.0f;
        }
        float fB = this.c.b(fD <= 1.0f ? fD : 1.0f);
        L0 l0 = M0.a;
        return (f2 * fB) + ((1 - fB) * f);
    }
}

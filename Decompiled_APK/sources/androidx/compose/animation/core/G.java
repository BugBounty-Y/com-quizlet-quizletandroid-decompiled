package androidx.compose.animation.core;

import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes.dex */
public final class G implements E {
    public final float a;
    public final C0251k0 b;

    public G(float f, float f2, float f3) {
        this.a = f3;
        C0251k0 c0251k0 = new C0251k0();
        c0251k0.a = 1.0f;
        double dSqrt = Math.sqrt(50.0d);
        c0251k0.b = dSqrt;
        c0251k0.g = 1.0f;
        if (f < DefinitionKt.NO_Float_VALUE) {
            throw new IllegalArgumentException("Damping ratio must be non-negative");
        }
        c0251k0.g = f;
        c0251k0.c = false;
        if (((float) (dSqrt * dSqrt)) <= DefinitionKt.NO_Float_VALUE) {
            throw new IllegalArgumentException("Spring stiffness constant must be positive.");
        }
        c0251k0.b = Math.sqrt(f2);
        c0251k0.c = false;
        this.b = c0251k0;
    }

    @Override // androidx.compose.animation.core.E
    public final float b(long j, float f, float f2, float f3) {
        C0251k0 c0251k0 = this.b;
        c0251k0.a = f2;
        return Float.intBitsToFloat((int) (c0251k0.a(f, f3, j / 1000000) & 4294967295L));
    }

    /* JADX WARN: Removed duplicated region for block: B:51:0x0171  */
    @Override // androidx.compose.animation.core.E
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final long c(float r37, float r38, float r39) {
        /*
            Method dump skipped, instructions count: 675
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.animation.core.G.c(float, float, float):long");
    }

    @Override // androidx.compose.animation.core.E
    public final float d(float f, float f2, float f3) {
        return DefinitionKt.NO_Float_VALUE;
    }

    @Override // androidx.compose.animation.core.E
    public final float e(long j, float f, float f2, float f3) {
        C0251k0 c0251k0 = this.b;
        c0251k0.a = f2;
        return Float.intBitsToFloat((int) (c0251k0.a(f, f3, j / 1000000) >> 32));
    }
}

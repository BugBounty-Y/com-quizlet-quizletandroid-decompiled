package androidx.compose.animation.core;

import com.skydoves.balloon.internals.DefinitionKt;

/* renamed from: androidx.compose.animation.core.x, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0274x implements B {
    public final float a;
    public final float b;
    public final float c;
    public final float d;
    public final float e;
    public final float f;

    public C0274x(float f, float f2, float f3, float f4) {
        int iF;
        this.a = f;
        this.b = f2;
        this.c = f3;
        this.d = f4;
        if (Float.isNaN(f) || Float.isNaN(f2) || Float.isNaN(f3) || Float.isNaN(f4)) {
            throw new IllegalArgumentException("Parameters to CubicBezierEasing cannot be NaN. Actual parameters are: " + f + ", " + f2 + ", " + f3 + ", " + f4 + '.');
        }
        float[] fArr = new float[5];
        float f5 = (f2 - DefinitionKt.NO_Float_VALUE) * 3.0f;
        float f6 = (f4 - f2) * 3.0f;
        float f7 = (1.0f - f4) * 3.0f;
        double d = f5;
        double d2 = f6;
        double d3 = f7;
        double d4 = d2 * 2.0d;
        double d5 = (d - d4) + d3;
        if (d5 == 0.0d) {
            iF = d2 == d3 ? 0 : androidx.compose.ui.graphics.F.F((float) ((d4 - d3) / (d4 - (d3 * 2.0d))), fArr, 0);
        } else {
            double d6 = -Math.sqrt((d2 * d2) - (d3 * d));
            double d7 = (-d) + d2;
            int iF2 = androidx.compose.ui.graphics.F.F((float) ((-(d6 + d7)) / d5), fArr, 0);
            iF = androidx.compose.ui.graphics.F.F((float) ((d6 - d7) / d5), fArr, iF2) + iF2;
            if (iF > 1) {
                float f8 = fArr[0];
                float f9 = fArr[1];
                if (f8 > f9) {
                    fArr[0] = f9;
                    fArr[1] = f8;
                } else if (f8 == f9) {
                    iF--;
                }
            }
        }
        float f10 = (f6 - f5) * 2.0f;
        int iF3 = androidx.compose.ui.graphics.F.F((-f10) / (((f7 - f6) * 2.0f) - f10), fArr, iF) + iF;
        float fMin = Math.min(DefinitionKt.NO_Float_VALUE, 1.0f);
        float fMax = Math.max(DefinitionKt.NO_Float_VALUE, 1.0f);
        for (int i = 0; i < iF3; i++) {
            float f11 = fArr[i];
            float f12 = (((((((((f2 - f4) * 3.0f) + 1.0f) - DefinitionKt.NO_Float_VALUE) * f11) + (((f4 - (f2 * 2.0f)) + DefinitionKt.NO_Float_VALUE) * 3.0f)) * f11) + f5) * f11) + DefinitionKt.NO_Float_VALUE;
            fMin = Math.min(fMin, f12);
            fMax = Math.max(fMax, f12);
        }
        long jFloatToRawIntBits = (Float.floatToRawIntBits(fMin) << 32) | (Float.floatToRawIntBits(fMax) & 4294967295L);
        this.e = Float.intBitsToFloat((int) (jFloatToRawIntBits >> 32));
        this.f = Float.intBitsToFloat((int) (jFloatToRawIntBits & 4294967295L));
    }

    /* JADX WARN: Removed duplicated region for block: B:107:0x01cb  */
    /* JADX WARN: Removed duplicated region for block: B:108:0x01cd  */
    /* JADX WARN: Removed duplicated region for block: B:17:0x007c  */
    /* JADX WARN: Removed duplicated region for block: B:22:0x0088  */
    /* JADX WARN: Removed duplicated region for block: B:28:0x00a9  */
    /* JADX WARN: Removed duplicated region for block: B:36:0x00bc A[PHI: r4
  0x00bc: PHI (r4v25 float) = (r4v15 float), (r4v20 float), (r4v34 float) binds: [B:67:0x014b, B:81:0x017a, B:35:0x00ba] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:37:0x00bf  */
    /* JADX WARN: Removed duplicated region for block: B:60:0x013a  */
    /* JADX WARN: Removed duplicated region for block: B:69:0x014f  */
    /* JADX WARN: Removed duplicated region for block: B:74:0x0169  */
    /* JADX WARN: Removed duplicated region for block: B:83:0x017e  */
    /* JADX WARN: Removed duplicated region for block: B:99:0x01b8  */
    @Override // androidx.compose.animation.core.B
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final float b(float r28) {
        /*
            Method dump skipped, instructions count: 614
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.animation.core.C0274x.b(float):float");
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof C0274x)) {
            return false;
        }
        C0274x c0274x = (C0274x) obj;
        return this.a == c0274x.a && this.b == c0274x.b && this.c == c0274x.c && this.d == c0274x.d;
    }

    public final int hashCode() {
        return Float.hashCode(this.d) + android.support.v4.media.session.a.b(android.support.v4.media.session.a.b(Float.hashCode(this.a) * 31, this.b, 31), this.c, 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("CubicBezierEasing(a=");
        sb.append(this.a);
        sb.append(", b=");
        sb.append(this.b);
        sb.append(", c=");
        sb.append(this.c);
        sb.append(", d=");
        return android.support.v4.media.session.a.p(sb, this.d, ')');
    }
}

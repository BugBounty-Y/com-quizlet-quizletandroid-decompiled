package androidx.compose.ui.graphics.colorspace;

import androidx.compose.ui.graphics.F;
import com.google.android.gms.internal.mlkit_vision_barcode.V5;
import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes.dex */
public final class l extends c {
    public static final float[] d;
    public static final float[] e;
    public static final float[] f;
    public static final float[] g;

    static {
        float[] fArrH = j.h(new float[]{0.818933f, 0.032984544f, 0.0482003f, 0.36186674f, 0.9293119f, 0.26436627f, -0.12885971f, 0.03614564f, 0.6338517f}, j.c(a.b.a, new float[]{0.964212f, 1.0f, 0.8251883f}, new float[]{0.95042855f, 1.0f, 1.0889004f}));
        d = fArrH;
        float[] fArr = {0.21045426f, 1.9779985f, 0.025904037f, 0.7936178f, -2.4285922f, 0.78277177f, -0.004072047f, 0.4505937f, -0.80867577f};
        e = fArr;
        f = j.g(fArrH);
        g = j.g(fArr);
    }

    @Override // androidx.compose.ui.graphics.colorspace.c
    public final float a(int i) {
        return i == 0 ? 1.0f : 0.5f;
    }

    @Override // androidx.compose.ui.graphics.colorspace.c
    public final float b(int i) {
        if (i == 0) {
            return DefinitionKt.NO_Float_VALUE;
        }
        return -0.5f;
    }

    @Override // androidx.compose.ui.graphics.colorspace.c
    public final long d(float f2, float f3, float f4) {
        if (f2 < DefinitionKt.NO_Float_VALUE) {
            f2 = 0.0f;
        }
        if (f2 > 1.0f) {
            f2 = 1.0f;
        }
        if (f3 < -0.5f) {
            f3 = -0.5f;
        }
        if (f3 > 0.5f) {
            f3 = 0.5f;
        }
        if (f4 < -0.5f) {
            f4 = -0.5f;
        }
        float f5 = f4 <= 0.5f ? f4 : 0.5f;
        float[] fArr = g;
        float f6 = (fArr[6] * f5) + (fArr[3] * f3) + (fArr[0] * f2);
        float f7 = (fArr[7] * f5) + (fArr[4] * f3) + (fArr[1] * f2);
        float f8 = (fArr[8] * f5) + (fArr[5] * f3) + (fArr[2] * f2);
        float f9 = f7 * f7 * f7;
        float f10 = f8 * f8 * f8;
        float[] fArr2 = f;
        float f11 = (fArr2[6] * f10) + (fArr2[3] * f9) + (fArr2[0] * f6 * f6 * f6);
        return (Float.floatToRawIntBits((fArr2[7] * f10) + (fArr2[4] * f9) + (fArr2[1] * r11)) & 4294967295L) | (Float.floatToRawIntBits(f11) << 32);
    }

    @Override // androidx.compose.ui.graphics.colorspace.c
    public final float e(float f2, float f3, float f4) {
        if (f2 < DefinitionKt.NO_Float_VALUE) {
            f2 = 0.0f;
        }
        if (f2 > 1.0f) {
            f2 = 1.0f;
        }
        if (f3 < -0.5f) {
            f3 = -0.5f;
        }
        if (f3 > 0.5f) {
            f3 = 0.5f;
        }
        if (f4 < -0.5f) {
            f4 = -0.5f;
        }
        float f5 = f4 <= 0.5f ? f4 : 0.5f;
        float[] fArr = g;
        float f6 = (fArr[6] * f5) + (fArr[3] * f3) + (fArr[0] * f2);
        float f7 = (fArr[7] * f5) + (fArr[4] * f3) + (fArr[1] * f2);
        float f8 = (fArr[8] * f5) + (fArr[5] * f3) + (fArr[2] * f2);
        float f9 = f6 * f6 * f6;
        float f10 = f7 * f7 * f7;
        float f11 = f8 * f8 * f8;
        float[] fArr2 = f;
        return (fArr2[8] * f11) + (fArr2[5] * f10) + (fArr2[2] * f9);
    }

    @Override // androidx.compose.ui.graphics.colorspace.c
    public final long f(float f2, float f3, float f4, float f5, c cVar) {
        float[] fArr = d;
        float f6 = (fArr[6] * f4) + (fArr[3] * f3) + (fArr[0] * f2);
        float f7 = (fArr[7] * f4) + (fArr[4] * f3) + (fArr[1] * f2);
        float f8 = (fArr[8] * f4) + (fArr[5] * f3) + (fArr[2] * f2);
        float fB = V5.b(f6);
        float fB2 = V5.b(f7);
        float fB3 = V5.b(f8);
        float[] fArr2 = e;
        return F.b((fArr2[6] * fB3) + (fArr2[3] * fB2) + (fArr2[0] * fB), (fArr2[7] * fB3) + (fArr2[4] * fB2) + (fArr2[1] * fB), (fArr2[8] * fB3) + (fArr2[5] * fB2) + (fArr2[2] * fB), f5, cVar);
    }
}

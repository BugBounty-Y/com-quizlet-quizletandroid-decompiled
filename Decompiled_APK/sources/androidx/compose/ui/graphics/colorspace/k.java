package androidx.compose.ui.graphics.colorspace;

import androidx.compose.ui.graphics.F;
import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes.dex */
public final class k extends c {
    public final /* synthetic */ int d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ k(long j, int i, int i2, String str) {
        super(i, j, str);
        this.d = i2;
    }

    @Override // androidx.compose.ui.graphics.colorspace.c
    public final float a(int i) {
        switch (this.d) {
            case 0:
                return i == 0 ? 100.0f : 128.0f;
            default:
                return 2.0f;
        }
    }

    @Override // androidx.compose.ui.graphics.colorspace.c
    public final float b(int i) {
        switch (this.d) {
            case 0:
                if (i == 0) {
                    return DefinitionKt.NO_Float_VALUE;
                }
                return -128.0f;
            default:
                return -2.0f;
        }
    }

    @Override // androidx.compose.ui.graphics.colorspace.c
    public final long d(float f, float f2, float f3) {
        switch (this.d) {
            case 0:
                if (f < DefinitionKt.NO_Float_VALUE) {
                    f = 0.0f;
                }
                if (f > 100.0f) {
                    f = 100.0f;
                }
                if (f2 < -128.0f) {
                    f2 = -128.0f;
                }
                if (f2 > 128.0f) {
                    f2 = 128.0f;
                }
                float f4 = (f + 16.0f) / 116.0f;
                float f5 = (f2 * 0.002f) + f4;
                float f6 = f5 > 0.20689656f ? f5 * f5 * f5 : (f5 - 0.13793103f) * 0.12841855f;
                float f7 = f4 > 0.20689656f ? f4 * f4 * f4 : (f4 - 0.13793103f) * 0.12841855f;
                float f8 = f6 * j.e[0];
                return (Float.floatToRawIntBits(f7 * r5[1]) & 4294967295L) | (Float.floatToRawIntBits(f8) << 32);
            default:
                if (f < -2.0f) {
                    f = -2.0f;
                }
                if (f > 2.0f) {
                    f = 2.0f;
                }
                if (f2 < -2.0f) {
                    f2 = -2.0f;
                }
                return (Float.floatToRawIntBits(f) << 32) | (Float.floatToRawIntBits(f2 <= 2.0f ? f2 : 2.0f) & 4294967295L);
        }
    }

    @Override // androidx.compose.ui.graphics.colorspace.c
    public final float e(float f, float f2, float f3) {
        switch (this.d) {
            case 0:
                if (f < DefinitionKt.NO_Float_VALUE) {
                    f = 0.0f;
                }
                if (f > 100.0f) {
                    f = 100.0f;
                }
                if (f3 < -128.0f) {
                    f3 = -128.0f;
                }
                if (f3 > 128.0f) {
                    f3 = 128.0f;
                }
                float f4 = ((f + 16.0f) / 116.0f) - (f3 * 0.005f);
                return (f4 > 0.20689656f ? f4 * f4 * f4 : 0.12841855f * (f4 - 0.13793103f)) * j.e[2];
            default:
                if (f3 < -2.0f) {
                    f3 = -2.0f;
                }
                if (f3 > 2.0f) {
                    return 2.0f;
                }
                return f3;
        }
    }

    @Override // androidx.compose.ui.graphics.colorspace.c
    public final long f(float f, float f2, float f3, float f4, c cVar) {
        switch (this.d) {
            case 0:
                float[] fArr = j.e;
                float f5 = f / fArr[0];
                float f6 = f2 / fArr[1];
                float f7 = f3 / fArr[2];
                float fCbrt = f5 > 0.008856452f ? (float) Math.cbrt(f5) : (f5 * 7.787037f) + 0.13793103f;
                float fCbrt2 = f6 > 0.008856452f ? (float) Math.cbrt(f6) : (f6 * 7.787037f) + 0.13793103f;
                float f8 = (116.0f * fCbrt2) - 16.0f;
                float f9 = (fCbrt - fCbrt2) * 500.0f;
                float fCbrt3 = (fCbrt2 - (f7 > 0.008856452f ? (float) Math.cbrt(f7) : (f7 * 7.787037f) + 0.13793103f)) * 200.0f;
                if (f8 < DefinitionKt.NO_Float_VALUE) {
                    f8 = 0.0f;
                }
                if (f8 > 100.0f) {
                    f8 = 100.0f;
                }
                if (f9 < -128.0f) {
                    f9 = -128.0f;
                }
                if (f9 > 128.0f) {
                    f9 = 128.0f;
                }
                if (fCbrt3 < -128.0f) {
                    fCbrt3 = -128.0f;
                }
                return F.b(f8, f9, fCbrt3 <= 128.0f ? fCbrt3 : 128.0f, f4, cVar);
            default:
                if (f < -2.0f) {
                    f = -2.0f;
                }
                if (f > 2.0f) {
                    f = 2.0f;
                }
                if (f2 < -2.0f) {
                    f2 = -2.0f;
                }
                if (f2 > 2.0f) {
                    f2 = 2.0f;
                }
                if (f3 < -2.0f) {
                    f3 = -2.0f;
                }
                return F.b(f, f2, f3 <= 2.0f ? f3 : 2.0f, f4, cVar);
        }
    }
}

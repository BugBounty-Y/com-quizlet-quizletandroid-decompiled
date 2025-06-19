package androidx.compose.ui.graphics.colorspace;

import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes.dex */
public abstract class j {
    public static final s a = new s(0.31006f, 0.31616f);
    public static final s b = new s(0.34567f, 0.3585f);
    public static final s c = new s(0.32168f, 0.33767f);
    public static final s d = new s(0.31271f, 0.32902f);
    public static final float[] e = {0.964212f, 1.0f, 0.825188f};

    public static c a(c cVar) {
        s sVar = b;
        a aVar = a.b;
        if (b.a(cVar.b, b.a)) {
            q qVar = (q) cVar;
            s sVar2 = qVar.d;
            if (!d(sVar2, sVar)) {
                return new q(qVar.a, qVar.h, sVar, h(c(aVar.a, sVar2.a(), sVar.a()), qVar.i), qVar.k, qVar.n, qVar.e, qVar.f, qVar.g, -1);
            }
        }
        return cVar;
    }

    public static float b(float[] fArr) {
        float f = fArr[0];
        float f2 = fArr[1];
        float f3 = fArr[2];
        float f4 = fArr[3];
        float f5 = fArr[4];
        float f6 = fArr[5];
        float f7 = (((((f3 * f6) + ((f2 * f5) + (f * f4))) - (f4 * f5)) - (f2 * f3)) - (f * f6)) * 0.5f;
        return f7 < DefinitionKt.NO_Float_VALUE ? -f7 : f7;
    }

    public static final float[] c(float[] fArr, float[] fArr2, float[] fArr3) {
        i(fArr, fArr2);
        i(fArr, fArr3);
        float[] fArr4 = {fArr3[0] / fArr2[0], fArr3[1] / fArr2[1], fArr3[2] / fArr2[2]};
        float[] fArrG = g(fArr);
        float f = fArr4[0];
        float f2 = fArr[0] * f;
        float f3 = fArr4[1];
        float f4 = fArr[1] * f3;
        float f5 = fArr4[2];
        return h(fArrG, new float[]{f2, f4, fArr[2] * f5, fArr[3] * f, fArr[4] * f3, fArr[5] * f5, f * fArr[6], f3 * fArr[7], f5 * fArr[8]});
    }

    public static final boolean d(s sVar, s sVar2) {
        if (sVar == sVar2) {
            return true;
        }
        return Math.abs(sVar.a - sVar2.a) < 0.001f && Math.abs(sVar.b - sVar2.b) < 0.001f;
    }

    public static final g e(c cVar, c cVar2) {
        if (cVar == cVar2) {
            return new e(cVar, cVar, 1);
        }
        long j = b.a;
        return (b.a(cVar.b, j) && b.a(cVar2.b, j)) ? new f((q) cVar, (q) cVar2) : new g(cVar, cVar2, 0);
    }

    public static float f(float f, float f2, float f3, float f4) {
        return (f * f4) - (f2 * f3);
    }

    public static final float[] g(float[] fArr) {
        float f = fArr[0];
        float f2 = fArr[3];
        float f3 = fArr[6];
        float f4 = fArr[1];
        float f5 = fArr[4];
        float f6 = fArr[7];
        float f7 = fArr[2];
        float f8 = fArr[5];
        float f9 = fArr[8];
        float f10 = (f5 * f9) - (f6 * f8);
        float f11 = (f6 * f7) - (f4 * f9);
        float f12 = (f4 * f8) - (f5 * f7);
        float f13 = (f3 * f12) + (f2 * f11) + (f * f10);
        float[] fArr2 = new float[fArr.length];
        fArr2[0] = f10 / f13;
        fArr2[1] = f11 / f13;
        fArr2[2] = f12 / f13;
        fArr2[3] = ((f3 * f8) - (f2 * f9)) / f13;
        fArr2[4] = ((f9 * f) - (f3 * f7)) / f13;
        fArr2[5] = ((f7 * f2) - (f8 * f)) / f13;
        fArr2[6] = ((f2 * f6) - (f3 * f5)) / f13;
        fArr2[7] = ((f3 * f4) - (f6 * f)) / f13;
        fArr2[8] = ((f * f5) - (f2 * f4)) / f13;
        return fArr2;
    }

    public static final float[] h(float[] fArr, float[] fArr2) {
        float f = fArr[0];
        float f2 = fArr2[0];
        float f3 = fArr[3];
        float f4 = fArr2[1];
        float f5 = fArr[6];
        float f6 = fArr2[2];
        float f7 = (f5 * f6) + (f3 * f4) + (f * f2);
        float f8 = fArr[1];
        float f9 = fArr[4];
        float f10 = fArr[7];
        float f11 = (f10 * f6) + (f9 * f4) + (f8 * f2);
        float f12 = fArr[2];
        float f13 = fArr[5];
        float f14 = fArr[8];
        float f15 = (f6 * f14) + (f4 * f13) + (f2 * f12);
        float f16 = fArr2[3];
        float f17 = fArr2[4];
        float f18 = fArr2[5];
        float f19 = (f5 * f18) + (f3 * f17) + (f * f16);
        float f20 = (f10 * f18) + (f9 * f17) + (f8 * f16);
        float f21 = (f18 * f14) + (f17 * f13) + (f16 * f12);
        float f22 = fArr2[6];
        float f23 = fArr2[7];
        float f24 = (f3 * f23) + (f * f22);
        float f25 = fArr2[8];
        return new float[]{f7, f11, f15, f19, f20, f21, (f5 * f25) + f24, (f10 * f25) + (f9 * f23) + (f8 * f22), (f14 * f25) + (f13 * f23) + (f12 * f22)};
    }

    public static final void i(float[] fArr, float[] fArr2) {
        float f = fArr2[0];
        float f2 = fArr2[1];
        float f3 = fArr2[2];
        fArr2[0] = (fArr[6] * f3) + (fArr[3] * f2) + (fArr[0] * f);
        fArr2[1] = (fArr[7] * f3) + (fArr[4] * f2) + (fArr[1] * f);
        fArr2[2] = (fArr[8] * f3) + (fArr[5] * f2) + (fArr[2] * f);
    }
}

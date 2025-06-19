package androidx.compose.animation.core;

import com.skydoves.balloon.internals.DefinitionKt;
import java.util.Arrays;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.animation.core.v, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0271v {
    public static float[] s;
    public final float a;
    public final float b;
    public final float c;
    public final float d;
    public final float e;
    public final float f;
    public final float g;
    public float h;
    public float i;
    public final float[] j;
    public final float k;
    public final float l;
    public final float m;
    public final float n;
    public final float o;
    public final float p;
    public final boolean q;
    public final boolean r;

    public C0271v(int i, float f, float f2, float f3, float f4, float f5, float f6) {
        boolean z;
        float f7;
        float f8;
        float f9 = f3;
        this.a = f;
        this.b = f2;
        this.c = f9;
        this.d = f4;
        this.e = f5;
        this.f = f6;
        float f10 = f5 - f9;
        float f11 = f6 - f4;
        int i2 = 1;
        float f12 = DefinitionKt.NO_Float_VALUE;
        boolean z2 = i == 1 || (i == 4 ? f11 > DefinitionKt.NO_Float_VALUE : !(i != 5 || f11 >= DefinitionKt.NO_Float_VALUE));
        this.q = z2;
        float f13 = f2 - f;
        float f14 = 1 / f13;
        this.k = f14;
        boolean z3 = 3 == i;
        if (z3 || Math.abs(f10) < 0.001f || Math.abs(f11) < 0.001f) {
            float fHypot = (float) Math.hypot(f11, f10);
            this.g = fHypot;
            this.p = fHypot * f14;
            this.n = f10 / f13;
            this.o = f11 / f13;
            this.j = new float[101];
            this.l = Float.NaN;
            this.m = Float.NaN;
            z = true;
        } else {
            this.j = new float[101];
            this.l = (z2 ? -1 : 1) * f10;
            this.m = f11 * (z2 ? 1 : -1);
            this.n = z2 ? f5 : f9;
            this.o = z2 ? f4 : f6;
            float f15 = f4 - f6;
            int length = com.google.mlkit.common.sdkinternal.b.k().length;
            float fHypot2 = 0.0f;
            float f16 = 0.0f;
            float f17 = 0.0f;
            int i3 = 0;
            while (i3 < length) {
                int i4 = i2;
                float f18 = f12;
                double radians = (float) Math.toRadians((i3 * 90.0d) / (com.google.mlkit.common.sdkinternal.b.k().length - i4));
                float fSin = ((float) Math.sin(radians)) * f10;
                float fCos = ((float) Math.cos(radians)) * f15;
                if (i3 > 0) {
                    f7 = f15;
                    f8 = fSin;
                    fHypot2 += (float) Math.hypot(fSin - f16, fCos - f17);
                    com.google.mlkit.common.sdkinternal.b.k()[i3] = fHypot2;
                } else {
                    f7 = f15;
                    f8 = fSin;
                }
                i3++;
                f15 = f7;
                f16 = f8;
                f17 = fCos;
                i2 = i4;
                f12 = f18;
            }
            int i5 = i2;
            float f19 = f12;
            this.g = fHypot2;
            int length2 = com.google.mlkit.common.sdkinternal.b.k().length;
            for (int i6 = 0; i6 < length2; i6++) {
                float[] fArrK = com.google.mlkit.common.sdkinternal.b.k();
                fArrK[i6] = fArrK[i6] / fHypot2;
            }
            float[] fArr = this.j;
            int length3 = fArr.length;
            for (int i7 = 0; i7 < length3; i7++) {
                float length4 = i7 / (fArr.length - i5);
                float[] fArrK2 = com.google.mlkit.common.sdkinternal.b.k();
                int length5 = fArrK2.length;
                Intrinsics.checkNotNullParameter(fArrK2, "<this>");
                int iBinarySearch = Arrays.binarySearch(fArrK2, 0, length5, length4);
                if (iBinarySearch >= 0) {
                    fArr[i7] = iBinarySearch / (com.google.mlkit.common.sdkinternal.b.k().length - i5);
                } else if (iBinarySearch == -1) {
                    fArr[i7] = f19;
                } else {
                    int i8 = -iBinarySearch;
                    int i9 = i8 - 2;
                    fArr[i7] = (((length4 - com.google.mlkit.common.sdkinternal.b.k()[i9]) / (com.google.mlkit.common.sdkinternal.b.k()[i8 - i5] - com.google.mlkit.common.sdkinternal.b.k()[i9])) + i9) / (com.google.mlkit.common.sdkinternal.b.k().length - i5);
                }
            }
            this.p = this.g * this.k;
            z = z3;
        }
        this.r = z;
    }

    public final float a() {
        float f = this.l * this.i;
        float fHypot = this.p / ((float) Math.hypot(f, (-this.m) * this.h));
        return this.q ? (-f) * fHypot : f * fHypot;
    }

    public final float b() {
        float f = this.l * this.i;
        float f2 = (-this.m) * this.h;
        float fHypot = this.p / ((float) Math.hypot(f, f2));
        return this.q ? (-f2) * fHypot : f2 * fHypot;
    }

    public final void c(float f) {
        float f2 = (this.q ? this.b - f : f - this.a) * this.k;
        float fA = DefinitionKt.NO_Float_VALUE;
        if (f2 > DefinitionKt.NO_Float_VALUE) {
            fA = 1.0f;
            if (f2 < 1.0f) {
                float[] fArr = this.j;
                float length = f2 * (fArr.length - 1);
                int i = (int) length;
                float f3 = fArr[i];
                fA = android.support.v4.media.session.a.a(fArr[i + 1], f3, length - i, f3);
            }
        }
        double d = fA * 1.5707964f;
        this.h = (float) Math.sin(d);
        this.i = (float) Math.cos(d);
    }
}

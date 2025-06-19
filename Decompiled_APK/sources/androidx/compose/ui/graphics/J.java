package androidx.compose.ui.graphics;

import androidx.camera.camera2.internal.q0;
import com.google.android.gms.internal.mlkit_vision_barcode.Q4;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.Arrays;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class J {
    public final float[] a;

    public static float[] a() {
        return new float[]{1.0f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 1.0f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 1.0f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 1.0f};
    }

    public static final long b(long j, float[] fArr) {
        float fD = androidx.compose.ui.geometry.b.d(j);
        float fE = androidx.compose.ui.geometry.b.e(j);
        float f = 1 / (((fArr[7] * fE) + (fArr[3] * fD)) + fArr[15]);
        if (Float.isInfinite(f) || Float.isNaN(f)) {
            f = DefinitionKt.NO_Float_VALUE;
        }
        return Q4.c(((fArr[4] * fE) + (fArr[0] * fD) + fArr[12]) * f, ((fArr[5] * fE) + (fArr[1] * fD) + fArr[13]) * f);
    }

    public static final void c(float[] fArr, q0 q0Var) {
        long jB = b(Q4.c(q0Var.b, q0Var.c), fArr);
        long jB2 = b(Q4.c(q0Var.b, q0Var.e), fArr);
        long jB3 = b(Q4.c(q0Var.d, q0Var.c), fArr);
        long jB4 = b(Q4.c(q0Var.d, q0Var.e), fArr);
        q0Var.b = Math.min(Math.min(androidx.compose.ui.geometry.b.d(jB), androidx.compose.ui.geometry.b.d(jB2)), Math.min(androidx.compose.ui.geometry.b.d(jB3), androidx.compose.ui.geometry.b.d(jB4)));
        q0Var.c = Math.min(Math.min(androidx.compose.ui.geometry.b.e(jB), androidx.compose.ui.geometry.b.e(jB2)), Math.min(androidx.compose.ui.geometry.b.e(jB3), androidx.compose.ui.geometry.b.e(jB4)));
        q0Var.d = Math.max(Math.max(androidx.compose.ui.geometry.b.d(jB), androidx.compose.ui.geometry.b.d(jB2)), Math.max(androidx.compose.ui.geometry.b.d(jB3), androidx.compose.ui.geometry.b.d(jB4)));
        q0Var.e = Math.max(Math.max(androidx.compose.ui.geometry.b.e(jB), androidx.compose.ui.geometry.b.e(jB2)), Math.max(androidx.compose.ui.geometry.b.e(jB3), androidx.compose.ui.geometry.b.e(jB4)));
    }

    public static final void d(float[] fArr) {
        int i = 0;
        while (i < 4) {
            int i2 = 0;
            while (i2 < 4) {
                fArr[(i2 * 4) + i] = i == i2 ? 1.0f : DefinitionKt.NO_Float_VALUE;
                i2++;
            }
            i++;
        }
    }

    public static final void e(float f, float[] fArr) {
        double d = (f * 3.141592653589793d) / 180.0d;
        float fCos = (float) Math.cos(d);
        float fSin = (float) Math.sin(d);
        float f2 = fArr[0];
        float f3 = fArr[4];
        float f4 = (fSin * f3) + (fCos * f2);
        float f5 = -fSin;
        float f6 = fArr[1];
        float f7 = fArr[5];
        float f8 = (fSin * f7) + (fCos * f6);
        float f9 = fArr[2];
        float f10 = fArr[6];
        float f11 = (fSin * f10) + (fCos * f9);
        float f12 = fArr[3];
        float f13 = fArr[7];
        fArr[0] = f4;
        fArr[1] = f8;
        fArr[2] = f11;
        fArr[3] = (fSin * f13) + (fCos * f12);
        fArr[4] = (f3 * fCos) + (f2 * f5);
        fArr[5] = (f7 * fCos) + (f6 * f5);
        fArr[6] = (f10 * fCos) + (f9 * f5);
        fArr[7] = (fCos * f13) + (f5 * f12);
    }

    public static final void f(float[] fArr, float f, float f2) {
        fArr[0] = fArr[0] * f;
        fArr[1] = fArr[1] * f;
        fArr[2] = fArr[2] * f;
        fArr[3] = fArr[3] * f;
        fArr[4] = fArr[4] * f2;
        fArr[5] = fArr[5] * f2;
        fArr[6] = fArr[6] * f2;
        fArr[7] = fArr[7] * f2;
        fArr[8] = fArr[8] * 1.0f;
        fArr[9] = fArr[9] * 1.0f;
        fArr[10] = fArr[10] * 1.0f;
        fArr[11] = fArr[11] * 1.0f;
    }

    public static final void g(float[] fArr, float[] fArr2) {
        float fK = F.k(fArr, 0, fArr2, 0);
        float fK2 = F.k(fArr, 0, fArr2, 1);
        float fK3 = F.k(fArr, 0, fArr2, 2);
        float fK4 = F.k(fArr, 0, fArr2, 3);
        float fK5 = F.k(fArr, 1, fArr2, 0);
        float fK6 = F.k(fArr, 1, fArr2, 1);
        float fK7 = F.k(fArr, 1, fArr2, 2);
        float fK8 = F.k(fArr, 1, fArr2, 3);
        float fK9 = F.k(fArr, 2, fArr2, 0);
        float fK10 = F.k(fArr, 2, fArr2, 1);
        float fK11 = F.k(fArr, 2, fArr2, 2);
        float fK12 = F.k(fArr, 2, fArr2, 3);
        float fK13 = F.k(fArr, 3, fArr2, 0);
        float fK14 = F.k(fArr, 3, fArr2, 1);
        float fK15 = F.k(fArr, 3, fArr2, 2);
        float fK16 = F.k(fArr, 3, fArr2, 3);
        fArr[0] = fK;
        fArr[1] = fK2;
        fArr[2] = fK3;
        fArr[3] = fK4;
        fArr[4] = fK5;
        fArr[5] = fK6;
        fArr[6] = fK7;
        fArr[7] = fK8;
        fArr[8] = fK9;
        fArr[9] = fK10;
        fArr[10] = fK11;
        fArr[11] = fK12;
        fArr[12] = fK13;
        fArr[13] = fK14;
        fArr[14] = fK15;
        fArr[15] = fK16;
    }

    public static final void h(float[] fArr, float f, float f2) {
        float f3 = (fArr[8] * DefinitionKt.NO_Float_VALUE) + (fArr[4] * f2) + (fArr[0] * f) + fArr[12];
        float f4 = (fArr[9] * DefinitionKt.NO_Float_VALUE) + (fArr[5] * f2) + (fArr[1] * f) + fArr[13];
        float f5 = (fArr[10] * DefinitionKt.NO_Float_VALUE) + (fArr[6] * f2) + (fArr[2] * f) + fArr[14];
        float f6 = (fArr[11] * DefinitionKt.NO_Float_VALUE) + (fArr[7] * f2) + (fArr[3] * f) + fArr[15];
        fArr[12] = f3;
        fArr[13] = f4;
        fArr[14] = f5;
        fArr[15] = f6;
    }

    public final boolean equals(Object obj) {
        if (obj instanceof J) {
            return Intrinsics.b(this.a, ((J) obj).a);
        }
        return false;
    }

    public final int hashCode() {
        return Arrays.hashCode(this.a);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("\n            |");
        float[] fArr = this.a;
        sb.append(fArr[0]);
        sb.append(' ');
        sb.append(fArr[1]);
        sb.append(' ');
        sb.append(fArr[2]);
        sb.append(' ');
        sb.append(fArr[3]);
        sb.append("|\n            |");
        sb.append(fArr[4]);
        sb.append(' ');
        sb.append(fArr[5]);
        sb.append(' ');
        sb.append(fArr[6]);
        sb.append(' ');
        sb.append(fArr[7]);
        sb.append("|\n            |");
        sb.append(fArr[8]);
        sb.append(' ');
        sb.append(fArr[9]);
        sb.append(' ');
        sb.append(fArr[10]);
        sb.append(' ');
        sb.append(fArr[11]);
        sb.append("|\n            |");
        sb.append(fArr[12]);
        sb.append(' ');
        sb.append(fArr[13]);
        sb.append(' ');
        sb.append(fArr[14]);
        sb.append(' ');
        sb.append(fArr[15]);
        sb.append("|\n        ");
        return kotlin.text.x.c(sb.toString());
    }
}

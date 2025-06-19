package androidx.compose.ui.graphics;

import android.graphics.Bitmap;
import android.graphics.BlendMode;
import android.graphics.Canvas;
import android.graphics.Matrix;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.PorterDuff;
import android.graphics.Rect;
import android.graphics.RectF;
import android.graphics.Shader;
import android.os.Build;
import com.google.android.gms.internal.mlkit_vision_barcode.O4;
import com.google.android.gms.internal.mlkit_vision_barcode.Q4;
import com.google.android.gms.internal.mlkit_vision_barcode.T4;
import com.google.android.gms.internal.mlkit_vision_barcode.V5;
import com.skydoves.balloon.internals.DefinitionKt;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public abstract class F {
    public static final com.quizlet.shared.usecase.folderstudymaterials.d a = new com.quizlet.shared.usecase.folderstudymaterials.d(2);
    public static Method b;
    public static Method c;
    public static boolean d;

    public static final int A(long j) {
        float[] fArr = androidx.compose.ui.graphics.colorspace.d.a;
        long jA = C0861v.a(j, androidx.compose.ui.graphics.colorspace.d.c) >>> 32;
        kotlin.C c2 = kotlin.D.b;
        return (int) jA;
    }

    public static final Bitmap.Config B(int i) {
        return i == 0 ? Bitmap.Config.ARGB_8888 : i == 1 ? Bitmap.Config.ALPHA_8 : i == 2 ? Bitmap.Config.RGB_565 : i == 3 ? Bitmap.Config.RGBA_F16 : i == 4 ? Bitmap.Config.HARDWARE : Bitmap.Config.ARGB_8888;
    }

    public static final androidx.compose.ui.geometry.c C(Rect rect) {
        return new androidx.compose.ui.geometry.c(rect.left, rect.top, rect.right, rect.bottom);
    }

    public static final androidx.compose.ui.geometry.c D(RectF rectF) {
        return new androidx.compose.ui.geometry.c(rectF.left, rectF.top, rectF.right, rectF.bottom);
    }

    public static final PorterDuff.Mode E(int i) {
        return i == 0 ? PorterDuff.Mode.CLEAR : i == 1 ? PorterDuff.Mode.SRC : i == 2 ? PorterDuff.Mode.DST : i == 3 ? PorterDuff.Mode.SRC_OVER : i == 4 ? PorterDuff.Mode.DST_OVER : i == 5 ? PorterDuff.Mode.SRC_IN : i == 6 ? PorterDuff.Mode.DST_IN : i == 7 ? PorterDuff.Mode.SRC_OUT : i == 8 ? PorterDuff.Mode.DST_OUT : i == 9 ? PorterDuff.Mode.SRC_ATOP : i == 10 ? PorterDuff.Mode.DST_ATOP : i == 11 ? PorterDuff.Mode.XOR : i == 12 ? PorterDuff.Mode.ADD : i == 14 ? PorterDuff.Mode.SCREEN : i == 15 ? PorterDuff.Mode.OVERLAY : i == 16 ? PorterDuff.Mode.DARKEN : i == 17 ? PorterDuff.Mode.LIGHTEN : i == 13 ? PorterDuff.Mode.MULTIPLY : PorterDuff.Mode.SRC_OVER;
    }

    /* JADX WARN: Removed duplicated region for block: B:6:0x000d A[PHI: r0
  0x000d: PHI (r0v2 float) = (r0v1 float), (r0v0 float) binds: [B:11:0x001c, B:5:0x000b] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:7:0x000f  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final int F(float r3, float[] r4, int r5) {
        /*
            r0 = 0
            int r1 = (r3 > r0 ? 1 : (r3 == r0 ? 0 : -1))
            r2 = 2143289344(0x7fc00000, float:NaN)
            if (r1 >= 0) goto L11
            r1 = -1251999744(0xffffffffb5600000, float:-8.34465E-7)
            int r3 = (r3 > r1 ? 1 : (r3 == r1 ? 0 : -1))
            if (r3 < 0) goto Lf
        Ld:
            r3 = r0
            goto L1f
        Lf:
            r3 = r2
            goto L1f
        L11:
            r0 = 1065353216(0x3f800000, float:1.0)
            int r1 = (r3 > r0 ? 1 : (r3 == r0 ? 0 : -1))
            if (r1 <= 0) goto L1f
            r1 = 1065353223(0x3f800007, float:1.0000008)
            int r3 = (r3 > r1 ? 1 : (r3 == r1 ? 0 : -1))
            if (r3 > 0) goto Lf
            goto Ld
        L1f:
            r4[r5] = r3
            boolean r3 = java.lang.Float.isNaN(r3)
            r3 = r3 ^ 1
            return r3
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.graphics.F.F(float, float[], int):int");
    }

    public static final C0844d a(C0848h c0848h) {
        Canvas canvas = AbstractC0845e.a;
        C0844d c0844d = new C0844d();
        c0844d.a = new Canvas(l(c0848h));
        return c0844d;
    }

    /* JADX WARN: Removed duplicated region for block: B:104:0x014d  */
    /* JADX WARN: Removed duplicated region for block: B:108:0x0154  */
    /* JADX WARN: Removed duplicated region for block: B:111:0x0161  */
    /* JADX WARN: Removed duplicated region for block: B:113:0x0166  */
    /* JADX WARN: Removed duplicated region for block: B:133:0x019f  */
    /* JADX WARN: Removed duplicated region for block: B:137:0x01a6  */
    /* JADX WARN: Removed duplicated region for block: B:73:0x00ec  */
    /* JADX WARN: Removed duplicated region for block: B:77:0x00f3  */
    /* JADX WARN: Removed duplicated region for block: B:80:0x0101  */
    /* JADX WARN: Removed duplicated region for block: B:84:0x0109  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final long b(float r20, float r21, float r22, float r23, androidx.compose.ui.graphics.colorspace.c r24) {
        /*
            Method dump skipped, instructions count: 480
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.graphics.F.b(float, float, float, float, androidx.compose.ui.graphics.colorspace.c):long");
    }

    public static final long c(int i) {
        long j = i;
        kotlin.C c2 = kotlin.D.b;
        long j2 = j << 32;
        int i2 = C0861v.h;
        return j2;
    }

    public static final long d(long j) {
        long j2 = j << 32;
        kotlin.C c2 = kotlin.D.b;
        int i = C0861v.h;
        return j2;
    }

    public static long e(int i, int i2, int i3) {
        return c(((i & 255) << 16) | (-16777216) | ((i2 & 255) << 8) | (i3 & 255));
    }

    public static C0848h f(int i, int i2, int i3) {
        androidx.compose.ui.graphics.colorspace.q qVar = androidx.compose.ui.graphics.colorspace.d.c;
        B(i3);
        return new C0848h(AbstractC0852l.b(i, i2, i3, true, qVar));
    }

    public static final com.google.android.gms.cloudmessaging.k g() {
        return new com.google.android.gms.cloudmessaging.k(new Paint(7));
    }

    public static final C0850j h() {
        return new C0850j(new Path());
    }

    public static final long i(float f, float f2) {
        long jFloatToRawIntBits = (Float.floatToRawIntBits(f2) & 4294967295L) | (Float.floatToRawIntBits(f) << 32);
        int i = Z.c;
        return jFloatToRawIntBits;
    }

    /* JADX WARN: Removed duplicated region for block: B:30:0x0094  */
    /* JADX WARN: Removed duplicated region for block: B:34:0x009b  */
    /* JADX WARN: Removed duplicated region for block: B:52:0x00e0  */
    /* JADX WARN: Removed duplicated region for block: B:56:0x00e6  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final long j(float r18, float r19, float r20, float r21, androidx.compose.ui.graphics.colorspace.c r22) {
        /*
            Method dump skipped, instructions count: 343
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.graphics.F.j(float, float, float, float, androidx.compose.ui.graphics.colorspace.c):long");
    }

    public static final float k(float[] fArr, int i, float[] fArr2, int i2) {
        int i3 = i * 4;
        return (fArr[i3 + 3] * fArr2[12 + i2]) + (fArr[i3 + 2] * fArr2[8 + i2]) + (fArr[i3 + 1] * fArr2[4 + i2]) + (fArr[i3] * fArr2[i2]);
    }

    public static final Bitmap l(C0848h c0848h) {
        if (c0848h instanceof C0848h) {
            return c0848h.a;
        }
        throw new UnsupportedOperationException("Unable to obtain android.graphics.Bitmap");
    }

    public static final long m(long j, long j2) {
        float f;
        float f2;
        long jA = C0861v.a(j, C0861v.f(j2));
        float fD = C0861v.d(j2);
        float fD2 = C0861v.d(jA);
        float f3 = 1.0f - fD2;
        float f4 = (fD * f3) + fD2;
        float fH = C0861v.h(jA);
        float fH2 = C0861v.h(j2);
        float f5 = DefinitionKt.NO_Float_VALUE;
        if (f4 == DefinitionKt.NO_Float_VALUE) {
            f = 0.0f;
        } else {
            f = (((fH2 * fD) * f3) + (fH * fD2)) / f4;
        }
        float fG = C0861v.g(jA);
        float fG2 = C0861v.g(j2);
        if (f4 == DefinitionKt.NO_Float_VALUE) {
            f2 = 0.0f;
        } else {
            f2 = (((fG2 * fD) * f3) + (fG * fD2)) / f4;
        }
        float fE = C0861v.e(jA);
        float fE2 = C0861v.e(j2);
        if (f4 != DefinitionKt.NO_Float_VALUE) {
            f5 = (((fE2 * fD) * f3) + (fE * fD2)) / f4;
        }
        return j(f, f2, f5, f4, C0861v.f(j2));
    }

    public static void n(androidx.compose.ui.graphics.drawscope.d dVar, N n, long j) {
        androidx.compose.ui.graphics.drawscope.g gVar = androidx.compose.ui.graphics.drawscope.g.a;
        if (n instanceof L) {
            androidx.compose.ui.geometry.c cVar = ((L) n).a;
            dVar.w0(j, Q4.c(cVar.a, cVar.b), T4.a(cVar.e(), cVar.d()), 1.0f, 3);
        } else {
            if (!(n instanceof M)) {
                if (!(n instanceof K)) {
                    throw new NoWhenBranchMatchedException();
                }
                dVar.g0(((K) n).a, j, 1.0f, gVar);
                return;
            }
            M m = (M) n;
            C0850j c0850j = m.b;
            if (c0850j != null) {
                dVar.g0(c0850j, j, 1.0f, gVar);
                return;
            }
            androidx.compose.ui.geometry.d dVar2 = m.a;
            float fB = androidx.compose.ui.geometry.a.b(dVar2.h);
            dVar.w(j, Q4.c(dVar2.a, dVar2.b), T4.a(dVar2.b(), dVar2.a()), O4.a(fB, fB), gVar);
        }
    }

    public static void o(Canvas canvas, boolean z) throws IllegalAccessException, NoSuchMethodException, SecurityException, IllegalArgumentException, InvocationTargetException {
        Method method;
        int i = Build.VERSION.SDK_INT;
        if (i >= 29) {
            C0860u.a.a(canvas, z);
            return;
        }
        if (!d) {
            try {
                if (i == 28) {
                    Method declaredMethod = Class.class.getDeclaredMethod("getDeclaredMethod", String.class, new Class[0].getClass());
                    b = (Method) declaredMethod.invoke(Canvas.class, "insertReorderBarrier", new Class[0]);
                    c = (Method) declaredMethod.invoke(Canvas.class, "insertInorderBarrier", new Class[0]);
                } else {
                    b = Canvas.class.getDeclaredMethod("insertReorderBarrier", null);
                    c = Canvas.class.getDeclaredMethod("insertInorderBarrier", null);
                }
                Method method2 = b;
                if (method2 != null) {
                    method2.setAccessible(true);
                }
                Method method3 = c;
                if (method3 != null) {
                    method3.setAccessible(true);
                }
            } catch (IllegalAccessException | NoSuchMethodException | InvocationTargetException unused) {
            }
            d = true;
        }
        if (z) {
            try {
                Method method4 = b;
                if (method4 != null) {
                    method4.invoke(canvas, null);
                }
            } catch (IllegalAccessException | InvocationTargetException unused2) {
                return;
            }
        }
        if (z || (method = c) == null) {
            return;
        }
        method.invoke(canvas, null);
    }

    public static final androidx.compose.ui.q p(androidx.compose.ui.q qVar, Function1 function1) {
        return qVar.g(new BlockGraphicsLayerElement(function1));
    }

    public static androidx.compose.ui.q q(androidx.compose.ui.q qVar, float f, float f2, float f3, float f4, float f5, V v, boolean z, int i) {
        float f6 = (i & 1) != 0 ? 1.0f : f;
        float f7 = (i & 2) != 0 ? 1.0f : f2;
        float f8 = (i & 4) != 0 ? 1.0f : f3;
        float f9 = (i & 32) != 0 ? 0.0f : f4;
        float f10 = (i & 256) != 0 ? 0.0f : f5;
        long j = Z.b;
        V v2 = (i & 2048) != 0 ? a : v;
        boolean z2 = (i & 4096) != 0 ? false : z;
        long j2 = G.a;
        return qVar.g(new GraphicsLayerElement(f6, f7, f8, f9, f10, j, v2, z2, j2, j2, (i & 65536) == 0 ? 1 : 0));
    }

    public static final long r(long j, long j2, float f) {
        androidx.compose.ui.graphics.colorspace.l lVar = androidx.compose.ui.graphics.colorspace.d.t;
        long jA = C0861v.a(j, lVar);
        long jA2 = C0861v.a(j2, lVar);
        float fD = C0861v.d(jA);
        float fH = C0861v.h(jA);
        float fG = C0861v.g(jA);
        float fE = C0861v.e(jA);
        float fD2 = C0861v.d(jA2);
        float fH2 = C0861v.h(jA2);
        float fG2 = C0861v.g(jA2);
        float fE2 = C0861v.e(jA2);
        if (f < DefinitionKt.NO_Float_VALUE) {
            f = 0.0f;
        }
        if (f > 1.0f) {
            f = 1.0f;
        }
        return C0861v.a(j(V5.c(fH, fH2, f), V5.c(fG, fG2, f), V5.c(fE, fE2, f), V5.c(fD, fD2, f), lVar), C0861v.f(j2));
    }

    public static final float s(long j) {
        androidx.compose.ui.graphics.colorspace.c cVarF = C0861v.f(j);
        if (!androidx.compose.ui.graphics.colorspace.b.a(cVarF.b, androidx.compose.ui.graphics.colorspace.b.a)) {
            throw new IllegalArgumentException("The specified color must be encoded in an RGB color space. The supplied color space is " + ((Object) androidx.compose.ui.graphics.colorspace.b.b(cVarF.b)));
        }
        double dH = C0861v.h(j);
        androidx.compose.ui.graphics.colorspace.m mVar = ((androidx.compose.ui.graphics.colorspace.q) cVarF).p;
        double d2 = mVar.d(dH);
        float fD = (float) ((mVar.d(C0861v.e(j)) * 0.0722d) + (mVar.d(C0861v.g(j)) * 0.7152d) + (d2 * 0.2126d));
        if (fD < DefinitionKt.NO_Float_VALUE) {
            fD = 0.0f;
        }
        if (fD > 1.0f) {
            return 1.0f;
        }
        return fD;
    }

    public static final void t(Matrix matrix, float[] fArr) {
        float f = fArr[0];
        float f2 = fArr[1];
        float f3 = fArr[2];
        float f4 = fArr[3];
        float f5 = fArr[4];
        float f6 = fArr[5];
        float f7 = fArr[6];
        float f8 = fArr[7];
        float f9 = fArr[8];
        float f10 = fArr[12];
        float f11 = fArr[13];
        float f12 = fArr[15];
        fArr[0] = f;
        fArr[1] = f5;
        fArr[2] = f10;
        fArr[3] = f2;
        fArr[4] = f6;
        fArr[5] = f11;
        fArr[6] = f4;
        fArr[7] = f8;
        fArr[8] = f12;
        matrix.setValues(fArr);
        fArr[0] = f;
        fArr[1] = f2;
        fArr[2] = f3;
        fArr[3] = f4;
        fArr[4] = f5;
        fArr[5] = f6;
        fArr[6] = f7;
        fArr[7] = f8;
        fArr[8] = f9;
    }

    public static final void u(Matrix matrix, float[] fArr) {
        matrix.getValues(fArr);
        float f = fArr[0];
        float f2 = fArr[1];
        float f3 = fArr[2];
        float f4 = fArr[3];
        float f5 = fArr[4];
        float f6 = fArr[5];
        float f7 = fArr[6];
        float f8 = fArr[7];
        float f9 = fArr[8];
        fArr[0] = f;
        fArr[1] = f4;
        fArr[2] = 0.0f;
        fArr[3] = f7;
        fArr[4] = f2;
        fArr[5] = f5;
        fArr[6] = 0.0f;
        fArr[7] = f8;
        fArr[8] = 0.0f;
        fArr[9] = 0.0f;
        fArr[10] = 1.0f;
        fArr[11] = 0.0f;
        fArr[12] = f3;
        fArr[13] = f6;
        fArr[14] = 0.0f;
        fArr[15] = f9;
    }

    public static final BlendMode v(int i) {
        return i == 0 ? BlendMode.CLEAR : i == 1 ? BlendMode.SRC : i == 2 ? BlendMode.DST : i == 3 ? BlendMode.SRC_OVER : i == 4 ? BlendMode.DST_OVER : i == 5 ? BlendMode.SRC_IN : i == 6 ? BlendMode.DST_IN : i == 7 ? BlendMode.SRC_OUT : i == 8 ? BlendMode.DST_OUT : i == 9 ? BlendMode.SRC_ATOP : i == 10 ? BlendMode.DST_ATOP : i == 11 ? BlendMode.XOR : i == 12 ? BlendMode.PLUS : i == 13 ? BlendMode.MODULATE : i == 14 ? BlendMode.SCREEN : i == 15 ? BlendMode.OVERLAY : i == 16 ? BlendMode.DARKEN : i == 17 ? BlendMode.LIGHTEN : i == 18 ? BlendMode.COLOR_DODGE : i == 19 ? BlendMode.COLOR_BURN : i == 20 ? BlendMode.HARD_LIGHT : i == 21 ? BlendMode.SOFT_LIGHT : i == 22 ? BlendMode.DIFFERENCE : i == 23 ? BlendMode.EXCLUSION : i == 24 ? BlendMode.MULTIPLY : i == 25 ? BlendMode.HUE : i == 26 ? BlendMode.SATURATION : i == 27 ? BlendMode.COLOR : i == 28 ? BlendMode.LUMINOSITY : BlendMode.SRC_OVER;
    }

    public static final Rect w(androidx.compose.ui.geometry.c cVar) {
        return new Rect((int) cVar.a, (int) cVar.b, (int) cVar.c, (int) cVar.d);
    }

    public static final Rect x(androidx.compose.ui.unit.i iVar) {
        return new Rect(iVar.a, iVar.b, iVar.c, iVar.d);
    }

    public static final RectF y(androidx.compose.ui.geometry.c cVar) {
        return new RectF(cVar.a, cVar.b, cVar.c, cVar.d);
    }

    public static final Shader.TileMode z(int i) {
        if (i == 0) {
            return Shader.TileMode.CLAMP;
        }
        if (i == 1) {
            return Shader.TileMode.REPEAT;
        }
        if (i == 2) {
            return Shader.TileMode.MIRROR;
        }
        if (i == 3 && Build.VERSION.SDK_INT >= 31) {
            return Y.a.b();
        }
        return Shader.TileMode.CLAMP;
    }
}

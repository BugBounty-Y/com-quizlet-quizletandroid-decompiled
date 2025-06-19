package androidx.compose.material3;

import androidx.compose.animation.core.C0274x;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.ui.layout.AbstractC0897s;
import com.skydoves.balloon.internals.DefinitionKt;

/* renamed from: androidx.compose.material3.j3, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractC0666j3 {
    public static final float a;
    public static final androidx.compose.ui.q b;
    public static final float c = 240;
    public static final float d;
    public static final float e;
    public static final C0274x f;

    static {
        float f2 = 10;
        a = f2;
        b = AbstractC0382e.w(androidx.compose.ui.semantics.m.a(AbstractC0897s.j(androidx.compose.ui.n.b, C0608e0.f), true, C0736u.u), DefinitionKt.NO_Float_VALUE, f2, 1);
        float f3 = androidx.compose.material3.tokens.v.c;
        d = f3;
        e = androidx.compose.material3.tokens.v.d - (f3 * 2);
        new C0274x(0.2f, DefinitionKt.NO_Float_VALUE, 0.8f, 1.0f);
        new C0274x(0.4f, DefinitionKt.NO_Float_VALUE, 1.0f, 1.0f);
        new C0274x(DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 0.65f, 1.0f);
        new C0274x(0.1f, DefinitionKt.NO_Float_VALUE, 0.45f, 1.0f);
        f = new C0274x(0.4f, DefinitionKt.NO_Float_VALUE, 0.2f, 1.0f);
    }

    /* JADX WARN: Removed duplicated region for block: B:36:0x0068  */
    /* JADX WARN: Removed duplicated region for block: B:43:0x0085  */
    /* JADX WARN: Removed duplicated region for block: B:53:0x00a7  */
    /* JADX WARN: Removed duplicated region for block: B:54:0x00a9  */
    /* JADX WARN: Removed duplicated region for block: B:57:0x00b0  */
    /* JADX WARN: Removed duplicated region for block: B:59:0x00be  */
    /* JADX WARN: Removed duplicated region for block: B:63:0x0215  */
    /* JADX WARN: Removed duplicated region for block: B:64:0x0217  */
    /* JADX WARN: Removed duplicated region for block: B:67:0x0223  */
    /* JADX WARN: Removed duplicated region for block: B:70:0x022c  */
    /* JADX WARN: Removed duplicated region for block: B:73:0x0234 A[PHI: r13
  0x0234: PHI (r13v26 long) = (r13v24 long), (r13v27 long) binds: [B:72:0x0232, B:68:0x0229] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:74:0x0237  */
    /* JADX WARN: Removed duplicated region for block: B:77:0x0241  */
    /* JADX WARN: Removed duplicated region for block: B:81:0x0249  */
    /* JADX WARN: Removed duplicated region for block: B:85:0x0274  */
    /* JADX WARN: Removed duplicated region for block: B:87:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void a(androidx.compose.ui.q r32, long r33, float r35, long r36, int r38, androidx.compose.runtime.InterfaceC0806l r39, int r40, int r41) {
        /*
            Method dump skipped, instructions count: 638
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.material3.AbstractC0666j3.a(androidx.compose.ui.q, long, float, long, int, androidx.compose.runtime.l, int, int):void");
    }

    /* JADX WARN: Removed duplicated region for block: B:101:0x0146  */
    /* JADX WARN: Removed duplicated region for block: B:104:0x0164  */
    /* JADX WARN: Removed duplicated region for block: B:105:0x0166  */
    /* JADX WARN: Removed duplicated region for block: B:108:0x016e  */
    /* JADX WARN: Removed duplicated region for block: B:109:0x0170  */
    /* JADX WARN: Removed duplicated region for block: B:120:0x0195  */
    /* JADX WARN: Removed duplicated region for block: B:122:0x019b  */
    /* JADX WARN: Removed duplicated region for block: B:128:0x01ac  */
    /* JADX WARN: Removed duplicated region for block: B:130:0x01b2  */
    /* JADX WARN: Removed duplicated region for block: B:136:0x01c0 A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:139:0x01c6  */
    /* JADX WARN: Removed duplicated region for block: B:92:0x011e  */
    /* JADX WARN: Removed duplicated region for block: B:93:0x0120  */
    /* JADX WARN: Removed duplicated region for block: B:97:0x0129  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void b(kotlin.jvm.functions.Function0 r23, androidx.compose.ui.q r24, long r25, long r27, int r29, float r30, kotlin.jvm.functions.Function1 r31, androidx.compose.runtime.InterfaceC0806l r32, int r33, int r34) {
        /*
            Method dump skipped, instructions count: 501
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.material3.AbstractC0666j3.b(kotlin.jvm.functions.Function0, androidx.compose.ui.q, long, long, int, float, kotlin.jvm.functions.Function1, androidx.compose.runtime.l, int, int):void");
    }

    public static final void c(androidx.compose.ui.graphics.drawscope.d dVar, float f2, float f3, long j, float f4, int i) {
        float fD = androidx.compose.ui.geometry.e.d(dVar.g());
        float fB = androidx.compose.ui.geometry.e.b(dVar.g());
        float f5 = 2;
        float f6 = fB / f5;
        boolean z = dVar.getLayoutDirection() == androidx.compose.ui.unit.k.a;
        float f7 = (z ? f2 : 1.0f - f3) * fD;
        float f8 = (z ? f3 : 1.0f - f2) * fD;
        if (i == 0 || fB > fD) {
            dVar.C(j, com.google.android.gms.internal.mlkit_vision_barcode.Q4.c(f7, f6), com.google.android.gms.internal.mlkit_vision_barcode.Q4.c(f8, f6), f4, (496 & 16) != 0 ? 0 : 0);
            return;
        }
        float f9 = f4 / f5;
        kotlin.ranges.f fVar = new kotlin.ranges.f(f9, fD - f9);
        float fFloatValue = ((Number) kotlin.ranges.l.e(Float.valueOf(f7), fVar)).floatValue();
        float fFloatValue2 = ((Number) kotlin.ranges.l.e(Float.valueOf(f8), fVar)).floatValue();
        if (Math.abs(f3 - f2) > DefinitionKt.NO_Float_VALUE) {
            dVar.C(j, com.google.android.gms.internal.mlkit_vision_barcode.Q4.c(fFloatValue, f6), com.google.android.gms.internal.mlkit_vision_barcode.Q4.c(fFloatValue2, f6), f4, (496 & 16) != 0 ? 0 : i);
        }
    }

    public static final void d(androidx.compose.ui.graphics.drawscope.d dVar, float f2, float f3, long j, androidx.compose.ui.graphics.drawscope.h hVar) {
        float f4 = 2;
        float f5 = hVar.a / f4;
        float fD = androidx.compose.ui.geometry.e.d(dVar.g()) - (f4 * f5);
        dVar.f0(j, f2, f3, com.google.android.gms.internal.mlkit_vision_barcode.Q4.c(f5, f5), com.google.android.gms.internal.mlkit_vision_barcode.T4.a(fD, fD), (768 & 64) != 0 ? 1.0f : DefinitionKt.NO_Float_VALUE, hVar);
    }
}

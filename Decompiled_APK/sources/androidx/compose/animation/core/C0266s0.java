package androidx.compose.animation.core;

import com.google.android.gms.internal.mlkit_vision_barcode.N5;
import com.google.android.gms.internal.mlkit_vision_barcode.P5;
import com.google.android.gms.internal.mlkit_vision_barcode.Q4;
import com.google.android.gms.internal.mlkit_vision_barcode.R5;
import com.google.android.gms.internal.mlkit_vision_barcode.T4;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;

/* renamed from: androidx.compose.animation.core.s0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0266s0 extends kotlin.jvm.internal.r implements Function1 {
    public static final C0266s0 b = new C0266s0(1, 0);
    public static final C0266s0 c = new C0266s0(1, 1);
    public static final C0266s0 d = new C0266s0(1, 2);
    public static final C0266s0 e = new C0266s0(1, 3);
    public static final C0266s0 f = new C0266s0(1, 4);
    public static final C0266s0 g = new C0266s0(1, 5);
    public static final C0266s0 h = new C0266s0(1, 6);
    public static final C0266s0 i = new C0266s0(1, 7);
    public static final C0266s0 j = new C0266s0(1, 8);
    public static final C0266s0 k = new C0266s0(1, 9);
    public static final C0266s0 l = new C0266s0(1, 10);
    public static final C0266s0 m = new C0266s0(1, 11);
    public static final C0266s0 n = new C0266s0(1, 12);
    public static final C0266s0 o = new C0266s0(1, 13);
    public static final C0266s0 p = new C0266s0(1, 14);
    public static final C0266s0 q = new C0266s0(1, 15);
    public static final C0266s0 r = new C0266s0(1, 16);
    public static final C0266s0 s = new C0266s0(1, 17);
    public static final C0266s0 t = new C0266s0(1, 18);
    public static final C0266s0 u = new C0266s0(1, 19);
    public static final C0266s0 v = new C0266s0(1, 20);
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C0266s0(int i2, int i3) {
        super(i2);
        this.a = i3;
    }

    /* JADX WARN: Type inference failed for: r2v0, types: [java.lang.Object, kotlin.k] */
    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                return Unit.a;
            case 1:
                ((Function0) obj).invoke();
                return Unit.a;
            case 2:
                C0247i0 c0247i0 = (C0247i0) obj;
                long j2 = c0247i0.g;
                ((androidx.compose.runtime.snapshots.v) I0.a.getValue()).d(c0247i0, d, c0247i0.h);
                long j3 = c0247i0.g;
                if (j2 != j3) {
                    X x = c0247i0.o;
                    if (x != null) {
                        x.g = j3;
                        if (x.b == null) {
                            x.h = kotlin.math.c.c((1.0d - x.e.a(0)) * c0247i0.g);
                        }
                    } else if (j3 != 0) {
                        c0247i0.c0();
                    }
                }
                return Unit.a;
            case 3:
                long j4 = ((androidx.compose.ui.unit.f) obj).a;
                return new C0262q(Float.intBitsToFloat((int) (j4 >> 32)), Float.intBitsToFloat((int) (j4 & 4294967295L)));
            case 4:
                C0262q c0262q = (C0262q) obj;
                return new androidx.compose.ui.unit.f(N5.b(c0262q.a, c0262q.b));
            case 5:
                return new C0260p(((androidx.compose.ui.unit.e) obj).a);
            case 6:
                return new androidx.compose.ui.unit.e(((C0260p) obj).a);
            case 7:
                return new C0260p(((Number) obj).floatValue());
            case 8:
                return Float.valueOf(((C0260p) obj).a);
            case 9:
                long j5 = ((androidx.compose.ui.unit.h) obj).a;
                return new C0262q((int) (j5 >> 32), (int) (j5 & 4294967295L));
            case 10:
                C0262q c0262q2 = (C0262q) obj;
                return new androidx.compose.ui.unit.h(P5.b(Math.round(c0262q2.a), Math.round(c0262q2.b)));
            case 11:
                long j6 = ((androidx.compose.ui.unit.j) obj).a;
                return new C0262q((int) (j6 >> 32), (int) (j6 & 4294967295L));
            case 12:
                C0262q c0262q3 = (C0262q) obj;
                int iRound = Math.round(c0262q3.a);
                if (iRound < 0) {
                    iRound = 0;
                }
                int iRound2 = Math.round(c0262q3.b);
                return new androidx.compose.ui.unit.j(R5.a(iRound, iRound2 >= 0 ? iRound2 : 0));
            case 13:
                return new C0260p(((Number) obj).intValue());
            case 14:
                return Integer.valueOf((int) ((C0260p) obj).a);
            case 15:
                long j7 = ((androidx.compose.ui.geometry.b) obj).a;
                return new C0262q(androidx.compose.ui.geometry.b.d(j7), androidx.compose.ui.geometry.b.e(j7));
            case 16:
                C0262q c0262q4 = (C0262q) obj;
                return new androidx.compose.ui.geometry.b(Q4.c(c0262q4.a, c0262q4.b));
            case 17:
                androidx.compose.ui.geometry.c cVar = (androidx.compose.ui.geometry.c) obj;
                return new C0265s(cVar.a, cVar.b, cVar.c, cVar.d);
            case 18:
                C0265s c0265s = (C0265s) obj;
                return new androidx.compose.ui.geometry.c(c0265s.a, c0265s.b, c0265s.c, c0265s.d);
            case 19:
                long j8 = ((androidx.compose.ui.geometry.e) obj).a;
                return new C0262q(androidx.compose.ui.geometry.e.d(j8), androidx.compose.ui.geometry.e.b(j8));
            default:
                C0262q c0262q5 = (C0262q) obj;
                return new androidx.compose.ui.geometry.e(T4.a(c0262q5.a, c0262q5.b));
        }
    }
}

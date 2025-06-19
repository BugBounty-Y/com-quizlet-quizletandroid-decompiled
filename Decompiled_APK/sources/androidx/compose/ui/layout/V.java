package androidx.compose.ui.layout;

import com.google.android.gms.internal.mlkit_vision_barcode.P5;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public abstract class V {
    public boolean a;

    /* JADX WARN: Multi-variable type inference failed */
    public static final void a(V v, W w) {
        v.getClass();
        if (w instanceof androidx.compose.ui.node.U) {
            ((androidx.compose.ui.node.U) w).S(v.a);
        }
    }

    public static void d(V v, W w, int i, int i2) {
        v.getClass();
        long jB = P5.b(i, i2);
        a(v, w);
        w.s0(androidx.compose.ui.unit.h.d(jB, w.e), DefinitionKt.NO_Float_VALUE, null);
    }

    public static void e(V v, W w, long j) {
        v.getClass();
        a(v, w);
        w.s0(androidx.compose.ui.unit.h.d(j, w.e), DefinitionKt.NO_Float_VALUE, null);
    }

    public static void f(V v, W w, int i, int i2) {
        long jB = P5.b(i, i2);
        if (v.b() == androidx.compose.ui.unit.k.a || v.c() == 0) {
            a(v, w);
            w.s0(androidx.compose.ui.unit.h.d(jB, w.e), DefinitionKt.NO_Float_VALUE, null);
        } else {
            long jB2 = P5.b((v.c() - w.a) - ((int) (jB >> 32)), (int) (jB & 4294967295L));
            a(v, w);
            w.s0(androidx.compose.ui.unit.h.d(jB2, w.e), DefinitionKt.NO_Float_VALUE, null);
        }
    }

    public static void g(V v, W w, int i, int i2) {
        int i3 = Y.b;
        X x = X.b;
        long jB = P5.b(i, i2);
        if (v.b() == androidx.compose.ui.unit.k.a || v.c() == 0) {
            a(v, w);
            w.s0(androidx.compose.ui.unit.h.d(jB, w.e), DefinitionKt.NO_Float_VALUE, x);
        } else {
            long jB2 = P5.b((v.c() - w.a) - ((int) (jB >> 32)), (int) (jB & 4294967295L));
            a(v, w);
            w.s0(androidx.compose.ui.unit.h.d(jB2, w.e), DefinitionKt.NO_Float_VALUE, x);
        }
    }

    public static void h(V v, W w, long j) {
        int i = Y.b;
        X x = X.b;
        if (v.b() == androidx.compose.ui.unit.k.a || v.c() == 0) {
            a(v, w);
            w.s0(androidx.compose.ui.unit.h.d(j, w.e), DefinitionKt.NO_Float_VALUE, x);
        } else {
            long jB = P5.b((v.c() - w.a) - ((int) (j >> 32)), (int) (j & 4294967295L));
            a(v, w);
            w.s0(androidx.compose.ui.unit.h.d(jB, w.e), DefinitionKt.NO_Float_VALUE, x);
        }
    }

    public static void i(V v, W w, int i, int i2, Function1 function1, int i3) {
        if ((i3 & 8) != 0) {
            int i4 = Y.b;
            function1 = X.b;
        }
        v.getClass();
        long jB = P5.b(i, i2);
        a(v, w);
        w.s0(androidx.compose.ui.unit.h.d(jB, w.e), DefinitionKt.NO_Float_VALUE, function1);
    }

    public static void j(V v, W w, long j) {
        int i = Y.b;
        X x = X.b;
        v.getClass();
        a(v, w);
        w.s0(androidx.compose.ui.unit.h.d(j, w.e), DefinitionKt.NO_Float_VALUE, x);
    }

    public abstract androidx.compose.ui.unit.k b();

    public abstract int c();
}

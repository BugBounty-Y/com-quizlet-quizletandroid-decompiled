package androidx.compose.runtime.internal;

import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.InterfaceC4938g;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.O;
import kotlin.jvm.internal.r;

/* loaded from: classes.dex */
public abstract class e {
    public static final Object a = new Object();
    public static final k b = new k(0, new long[0], new Object[0]);

    public static final int a(int i, int i2) {
        return i << (((i2 % 10) * 3) + 1);
    }

    public static final d b(InterfaceC0806l interfaceC0806l, int i, r rVar) {
        d dVar;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.U(Integer.rotateLeft(i, 1), a);
        Object objI = c0814p.I();
        if (objI == C0804k.a) {
            dVar = new d(true, i, rVar);
            c0814p.i0(dVar);
        } else {
            Intrinsics.e(objI, "null cannot be cast to non-null type androidx.compose.runtime.internal.ComposableLambdaImpl");
            dVar = (d) objI;
            dVar.g(rVar);
        }
        c0814p.p(false);
        return dVar;
    }

    public static final long c() {
        return Thread.currentThread().getId();
    }

    public static final void d(C0814p c0814p, Function2 function2) {
        Intrinsics.e(function2, "null cannot be cast to non-null type kotlin.Function2<androidx.compose.runtime.Composer, kotlin.Int, kotlin.Unit>");
        O.d(2, function2);
        function2.invoke(c0814p, 1);
    }

    public static final d e(int i, InterfaceC4938g interfaceC4938g, InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        Object objI = c0814p.I();
        if (objI == C0804k.a) {
            objI = new d(true, i, interfaceC4938g);
            c0814p.i0(objI);
        }
        d dVar = (d) objI;
        dVar.g(interfaceC4938g);
        return dVar;
    }

    public static final boolean f(C0813o0 c0813o0, C0813o0 c0813o02) {
        if (c0813o0 == null) {
            return true;
        }
        if (c0813o0 instanceof C0813o0) {
            return !c0813o0.b() || c0813o0.equals(c0813o02) || Intrinsics.b(c0813o0.c, c0813o02.c);
        }
        return false;
    }
}

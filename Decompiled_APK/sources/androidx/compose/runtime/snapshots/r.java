package androidx.compose.runtime.snapshots;

import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public abstract class r {
    public static final Object a = new Object();
    public static final Object b = new Object();

    public static final void a(int i, int i2) {
        if (i < 0 || i >= i2) {
            throw new IndexOutOfBoundsException("index (" + i + ") is out of bound of [0, " + i2 + ')');
        }
    }

    public static final int b(long[] jArr, long j) {
        int length = jArr.length - 1;
        int i = 0;
        while (i <= length) {
            int i2 = (i + length) >>> 1;
            long j2 = jArr[i2];
            if (j > j2) {
                i = i2 + 1;
            } else {
                if (j >= j2) {
                    return i2;
                }
                length = i2 - 1;
            }
        }
        return -(i + 1);
    }

    public static h d() {
        return (h) m.a.c();
    }

    public static h e(h hVar) {
        if (hVar instanceof E) {
            E e = (E) hVar;
            if (e.t == androidx.compose.runtime.internal.e.c()) {
                e.r = null;
                return hVar;
            }
        }
        if (hVar instanceof F) {
            F f = (F) hVar;
            if (f.h == androidx.compose.runtime.internal.e.c()) {
                f.g = null;
                return hVar;
            }
        }
        h hVarH = m.h(hVar, null, false);
        hVarH.j();
        return hVarH;
    }

    public static Object f(Function0 function0, Function1 function1) {
        h e;
        if (function1 == null) {
            return function0.invoke();
        }
        h hVar = (h) m.a.c();
        if (hVar instanceof E) {
            E e2 = (E) hVar;
            if (e2.t == androidx.compose.runtime.internal.e.c()) {
                Function1 function12 = e2.r;
                Function1 function13 = e2.s;
                try {
                    ((E) hVar).r = m.l(function1, function12, true);
                    ((E) hVar).s = function13;
                    return function0.invoke();
                } finally {
                    e2.r = function12;
                    e2.s = function13;
                }
            }
        }
        if (hVar == null || (hVar instanceof C0824d)) {
            e = new E(hVar instanceof C0824d ? (C0824d) hVar : null, function1, null, true, false);
        } else {
            if (function1 == null) {
                return function0.invoke();
            }
            e = hVar.u(function1);
        }
        try {
            h hVarJ = e.j();
            try {
                Object objInvoke = function0.invoke();
                h.q(hVarJ);
                return objInvoke;
            } catch (Throwable th) {
                h.q(hVarJ);
                throw th;
            }
        } finally {
            e.c();
        }
    }

    public static void g(h hVar, h hVar2, Function1 function1) {
        if (hVar != hVar2) {
            hVar2.getClass();
            h.q(hVar);
            hVar2.c();
        } else if (hVar instanceof E) {
            ((E) hVar).r = function1;
        } else if (hVar instanceof F) {
            ((F) hVar).g = function1;
        } else {
            throw new IllegalStateException(("Non-transparent snapshot was reused: " + hVar).toString());
        }
    }

    public static final void h() {
        throw new UnsupportedOperationException();
    }

    public abstract void c();
}

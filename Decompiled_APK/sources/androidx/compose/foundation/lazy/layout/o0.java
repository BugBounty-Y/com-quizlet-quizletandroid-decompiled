package androidx.compose.foundation.lazy.layout;

import android.os.Trace;
import java.util.List;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class o0 implements b0 {
    public final int a;
    public final long b;
    public final p0 c;
    public androidx.compose.ui.layout.c0 d;
    public boolean e;
    public boolean f;
    public boolean g;
    public n0 h;
    public boolean i;
    public final /* synthetic */ com.quizlet.data.interactor.set.c j;

    public o0(com.quizlet.data.interactor.set.c cVar, int i, long j, p0 p0Var) {
        this.j = cVar;
        this.a = i;
        this.b = j;
        this.c = p0Var;
    }

    @Override // androidx.compose.foundation.lazy.layout.b0
    public final void a() {
        this.i = true;
    }

    /* JADX WARN: Type inference failed for: r11v2, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.r] */
    public final boolean b(C0429a c0429a) {
        List list;
        n0 n0Var;
        if (c()) {
            Object objC = ((N) ((M) this.j.a).b.invoke()).c(this.a);
            boolean z = this.d != null;
            p0 p0Var = this.c;
            if (!z) {
                long jC = (objC == null || ((androidx.collection.H) p0Var.c).b(objC) < 0) ? p0Var.a : ((androidx.collection.H) p0Var.c).c(objC);
                long jA = c0429a.a();
                if ((!this.i || jA <= 0) && jC >= jA) {
                    return true;
                }
                long jNanoTime = System.nanoTime();
                Trace.beginSection("compose:lazy:prefetch:compose");
                try {
                    d();
                    Unit unit = Unit.a;
                    Trace.endSection();
                    long jNanoTime2 = System.nanoTime() - jNanoTime;
                    if (objC != null) {
                        androidx.collection.H h = (androidx.collection.H) p0Var.c;
                        int iB = h.b(objC);
                        ((androidx.collection.H) p0Var.c).e(p0.d(p0Var, jNanoTime2, iB >= 0 ? h.c[iB] : 0L), objC);
                    }
                    p0Var.a = p0.d(p0Var, jNanoTime2, p0Var.a);
                } finally {
                }
            }
            if (!this.i) {
                if (!this.g) {
                    if (c0429a.a() <= 0) {
                        return true;
                    }
                    Trace.beginSection("compose:lazy:prefetch:resolve-nested");
                    try {
                        androidx.compose.ui.layout.c0 c0Var = this.d;
                        if (c0Var == null) {
                            throw new IllegalArgumentException("Should precompose before resolving nested prefetch states");
                        }
                        kotlin.jvm.internal.J j = new kotlin.jvm.internal.J();
                        c0Var.b(new androidx.compose.foundation.layout.Y(j, 2));
                        List list2 = (List) j.a;
                        if (list2 != null) {
                            n0Var = new n0();
                            n0Var.e = this;
                            n0Var.c = list2;
                            n0Var.d = new List[list2.size()];
                            if (list2.isEmpty()) {
                                throw new IllegalArgumentException("NestedPrefetchController shouldn't be created with no states");
                            }
                        } else {
                            n0Var = null;
                        }
                        this.h = n0Var;
                        this.g = true;
                        Unit unit2 = Unit.a;
                    } finally {
                    }
                }
                n0 n0Var2 = this.h;
                if (n0Var2 != null) {
                    List[] listArr = (List[]) n0Var2.d;
                    int i = n0Var2.a;
                    List list3 = (List) n0Var2.c;
                    if (i < list3.size()) {
                        if (((o0) n0Var2.e).f) {
                            throw new IllegalStateException("Should not execute nested prefetch on canceled request");
                        }
                        Trace.beginSection("compose:lazy:prefetch:nested");
                        while (n0Var2.a < list3.size()) {
                            try {
                                if (listArr[n0Var2.a] == null) {
                                    if (c0429a.a() <= 0) {
                                        return true;
                                    }
                                    int i2 = n0Var2.a;
                                    c0 c0Var2 = (c0) list3.get(i2);
                                    ?? r11 = c0Var2.a;
                                    if (r11 == 0) {
                                        list = kotlin.collections.K.a;
                                    } else {
                                        a0 a0Var = new a0(c0Var2);
                                        r11.invoke(a0Var);
                                        list = a0Var.a;
                                    }
                                    listArr[i2] = list;
                                }
                                List list4 = listArr[n0Var2.a];
                                Intrinsics.d(list4);
                                while (n0Var2.b < list4.size()) {
                                    if (((o0) list4.get(n0Var2.b)).b(c0429a)) {
                                        return true;
                                    }
                                    n0Var2.b++;
                                }
                                n0Var2.b = 0;
                                n0Var2.a++;
                            } catch (Throwable th) {
                                throw th;
                            }
                        }
                        Unit unit3 = Unit.a;
                    }
                }
            }
            if (!this.e) {
                long j2 = this.b;
                if (!androidx.compose.ui.unit.a.k(j2)) {
                    long jC2 = (objC == null || ((androidx.collection.H) p0Var.d).b(objC) < 0) ? p0Var.b : ((androidx.collection.H) p0Var.d).c(objC);
                    long jA2 = c0429a.a();
                    if ((!this.i || jA2 <= 0) && jC2 >= jA2) {
                        return true;
                    }
                    long jNanoTime3 = System.nanoTime();
                    Trace.beginSection("compose:lazy:prefetch:measure");
                    try {
                        e(j2);
                        Unit unit4 = Unit.a;
                        Trace.endSection();
                        long jNanoTime4 = System.nanoTime() - jNanoTime3;
                        if (objC != null) {
                            androidx.collection.H h2 = (androidx.collection.H) p0Var.d;
                            int iB2 = h2.b(objC);
                            ((androidx.collection.H) p0Var.d).e(p0.d(p0Var, jNanoTime4, iB2 >= 0 ? h2.c[iB2] : 0L), objC);
                        }
                        p0Var.b = p0.d(p0Var, jNanoTime4, p0Var.b);
                        return false;
                    } finally {
                    }
                }
            }
        }
        return false;
    }

    public final boolean c() {
        if (this.f) {
            return false;
        }
        int iD = ((N) ((M) this.j.a).b.invoke()).d();
        int i = this.a;
        return i >= 0 && i < iD;
    }

    @Override // androidx.compose.foundation.lazy.layout.b0
    public final void cancel() {
        if (this.f) {
            return;
        }
        this.f = true;
        androidx.compose.ui.layout.c0 c0Var = this.d;
        if (c0Var != null) {
            c0Var.dispose();
        }
        this.d = null;
    }

    public final void d() {
        if (!c()) {
            throw new IllegalArgumentException("Callers should check whether the request is still valid before calling performComposition()");
        }
        if (this.d != null) {
            throw new IllegalArgumentException("Request was already composed!");
        }
        com.quizlet.data.interactor.set.c cVar = this.j;
        N n = (N) ((M) cVar.a).b.invoke();
        int i = this.a;
        Object objB = n.b(i);
        this.d = ((androidx.compose.ui.layout.e0) cVar.b).a().g(objB, ((M) cVar.a).a(i, objB, n.c(i)));
    }

    public final void e(long j) {
        if (this.f) {
            throw new IllegalArgumentException("Callers should check whether the request is still valid before calling performMeasure()");
        }
        if (this.e) {
            throw new IllegalArgumentException("Request was already measured!");
        }
        this.e = true;
        androidx.compose.ui.layout.c0 c0Var = this.d;
        if (c0Var == null) {
            throw new IllegalArgumentException("performComposition() must be called before performMeasure()");
        }
        int iA = c0Var.a();
        for (int i = 0; i < iA; i++) {
            c0Var.c(i, j);
        }
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("HandleAndRequestImpl { index = ");
        sb.append(this.a);
        sb.append(", constraints = ");
        sb.append((Object) androidx.compose.ui.unit.a.l(this.b));
        sb.append(", isComposed = ");
        sb.append(this.d != null);
        sb.append(", isMeasured = ");
        sb.append(this.e);
        sb.append(", isCanceled = ");
        return android.support.v4.media.session.a.o(" }", sb, this.f);
    }
}

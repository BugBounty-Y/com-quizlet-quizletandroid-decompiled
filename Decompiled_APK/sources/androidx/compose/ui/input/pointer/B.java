package androidx.compose.ui.input.pointer;

import androidx.compose.runtime.C0775b0;
import androidx.compose.ui.node.AbstractC0910f;
import androidx.compose.ui.node.l0;
import java.util.ArrayList;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C5028l;
import kotlinx.coroutines.D;
import kotlinx.coroutines.E;
import kotlinx.coroutines.y0;

/* loaded from: classes.dex */
public final class B extends androidx.compose.ui.p implements androidx.compose.ui.unit.b, l0 {
    public Object n;
    public Object o;
    public Function2 p;
    public y0 q;
    public f u;
    public f r = v.a;
    public final androidx.compose.runtime.collection.b s = new androidx.compose.runtime.collection.b(new z[16]);
    public final androidx.compose.runtime.collection.b t = new androidx.compose.runtime.collection.b(new z[16]);
    public long v = 0;

    public B(Object obj, Object obj2, Function2 function2) {
        this.n = obj;
        this.o = obj2;
        this.p = function2;
    }

    /* JADX WARN: Type inference failed for: r5v1, types: [java.lang.Object, java.util.List] */
    @Override // androidx.compose.ui.node.l0
    public final void E(f fVar, g gVar, long j) {
        this.v = j;
        if (gVar == g.a) {
            this.r = fVar;
        }
        if (this.q == null) {
            this.q = E.A(A0(), null, D.d, new A(this, null), 1);
        }
        N0(fVar, gVar);
        ?? r5 = fVar.a;
        int size = r5.size();
        int i = 0;
        while (true) {
            if (i >= size) {
                fVar = null;
                break;
            } else if (!l.c((n) r5.get(i))) {
                break;
            } else {
                i++;
            }
        }
        this.u = fVar;
    }

    /* JADX WARN: Type inference failed for: r1v1, types: [java.lang.Object, java.util.List] */
    @Override // androidx.compose.ui.node.l0
    public final void F() {
        f fVar = this.u;
        if (fVar == null) {
            return;
        }
        ?? r1 = fVar.a;
        int size = r1.size();
        for (int i = 0; i < size; i++) {
            if (((n) r1.get(i)).d) {
                ArrayList arrayList = new ArrayList(r1.size());
                int size2 = r1.size();
                for (int i2 = 0; i2 < size2; i2++) {
                    n nVar = (n) r1.get(i2);
                    long j = nVar.a;
                    boolean z = nVar.d;
                    long j2 = nVar.b;
                    long j3 = nVar.c;
                    arrayList.add(new n(j, j2, j3, false, nVar.e, j2, j3, z, z, 1, 0L));
                }
                f fVar2 = new f(arrayList, null);
                this.r = fVar2;
                N0(fVar2, g.a);
                N0(fVar2, g.b);
                N0(fVar2, g.c);
                this.u = null;
                return;
            }
        }
    }

    @Override // androidx.compose.ui.p
    public final void F0() {
        O0();
    }

    public final Object M0(Function2 function2, kotlin.coroutines.h frame) {
        kotlin.coroutines.intrinsics.a aVar;
        C5028l c5028l = new C5028l(1, kotlin.coroutines.intrinsics.h.b(frame));
        c5028l.r();
        z completion = new z(this, c5028l);
        synchronized (this.s) {
            this.s.b(completion);
            Intrinsics.checkNotNullParameter(function2, "<this>");
            Intrinsics.checkNotNullParameter(completion, "completion");
            kotlin.coroutines.h hVarB = kotlin.coroutines.intrinsics.h.b(kotlin.coroutines.intrinsics.h.a(completion, completion, function2));
            aVar = kotlin.coroutines.intrinsics.a.a;
            kotlin.coroutines.p pVar = new kotlin.coroutines.p(hVarB, aVar);
            kotlin.p pVar2 = kotlin.r.b;
            pVar.resumeWith(Unit.a);
        }
        c5028l.u(new C0775b0(completion, 15));
        Object objQ = c5028l.q();
        if (objQ == aVar) {
            Intrinsics.checkNotNullParameter(frame, "frame");
        }
        return objQ;
    }

    /* JADX WARN: Removed duplicated region for block: B:25:0x003e A[Catch: all -> 0x003c, TryCatch #1 {all -> 0x003c, blocks: (B:6:0x000e, B:12:0x001b, B:14:0x0021, B:15:0x0024, B:17:0x002c, B:19:0x0030, B:20:0x0037, B:25:0x003e, B:27:0x0044, B:28:0x0047, B:30:0x004f, B:32:0x0053), top: B:44:0x000e }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void N0(androidx.compose.ui.input.pointer.f r8, androidx.compose.ui.input.pointer.g r9) {
        /*
            r7 = this;
            r0 = 1
            androidx.compose.runtime.collection.b r1 = r7.s
            monitor-enter(r1)
            androidx.compose.runtime.collection.b r2 = r7.t     // Catch: java.lang.Throwable -> L69
            androidx.compose.runtime.collection.b r3 = r7.s     // Catch: java.lang.Throwable -> L69
            int r4 = r2.c     // Catch: java.lang.Throwable -> L69
            r2.c(r4, r3)     // Catch: java.lang.Throwable -> L69
            monitor-exit(r1)
            int r1 = r9.ordinal()     // Catch: java.lang.Throwable -> L3c
            r2 = 0
            if (r1 == 0) goto L3e
            if (r1 == r0) goto L1b
            r3 = 2
            if (r1 == r3) goto L3e
            goto L5d
        L1b:
            androidx.compose.runtime.collection.b r1 = r7.t     // Catch: java.lang.Throwable -> L3c
            int r3 = r1.c     // Catch: java.lang.Throwable -> L3c
            if (r3 <= 0) goto L5d
            int r3 = r3 - r0
            java.lang.Object[] r0 = r1.a     // Catch: java.lang.Throwable -> L3c
        L24:
            r1 = r0[r3]     // Catch: java.lang.Throwable -> L3c
            androidx.compose.ui.input.pointer.z r1 = (androidx.compose.ui.input.pointer.z) r1     // Catch: java.lang.Throwable -> L3c
            androidx.compose.ui.input.pointer.g r4 = r1.d     // Catch: java.lang.Throwable -> L3c
            if (r9 != r4) goto L37
            kotlinx.coroutines.l r4 = r1.c     // Catch: java.lang.Throwable -> L3c
            if (r4 == 0) goto L37
            r1.c = r2     // Catch: java.lang.Throwable -> L3c
            kotlin.p r1 = kotlin.r.b     // Catch: java.lang.Throwable -> L3c
            r4.resumeWith(r8)     // Catch: java.lang.Throwable -> L3c
        L37:
            int r3 = r3 + (-1)
            if (r3 >= 0) goto L24
            goto L5d
        L3c:
            r8 = move-exception
            goto L63
        L3e:
            androidx.compose.runtime.collection.b r1 = r7.t     // Catch: java.lang.Throwable -> L3c
            int r3 = r1.c     // Catch: java.lang.Throwable -> L3c
            if (r3 <= 0) goto L5d
            java.lang.Object[] r1 = r1.a     // Catch: java.lang.Throwable -> L3c
            r4 = 0
        L47:
            r5 = r1[r4]     // Catch: java.lang.Throwable -> L3c
            androidx.compose.ui.input.pointer.z r5 = (androidx.compose.ui.input.pointer.z) r5     // Catch: java.lang.Throwable -> L3c
            androidx.compose.ui.input.pointer.g r6 = r5.d     // Catch: java.lang.Throwable -> L3c
            if (r9 != r6) goto L5a
            kotlinx.coroutines.l r6 = r5.c     // Catch: java.lang.Throwable -> L3c
            if (r6 == 0) goto L5a
            r5.c = r2     // Catch: java.lang.Throwable -> L3c
            kotlin.p r5 = kotlin.r.b     // Catch: java.lang.Throwable -> L3c
            r6.resumeWith(r8)     // Catch: java.lang.Throwable -> L3c
        L5a:
            int r4 = r4 + r0
            if (r4 < r3) goto L47
        L5d:
            androidx.compose.runtime.collection.b r8 = r7.t
            r8.i()
            return
        L63:
            androidx.compose.runtime.collection.b r9 = r7.t
            r9.i()
            throw r8
        L69:
            r8 = move-exception
            monitor-exit(r1)
            throw r8
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.input.pointer.B.N0(androidx.compose.ui.input.pointer.f, androidx.compose.ui.input.pointer.g):void");
    }

    public final void O0() {
        y0 y0Var = this.q;
        if (y0Var != null) {
            y0Var.z(new PointerInputResetException());
            this.q = null;
        }
    }

    @Override // androidx.compose.ui.node.l0
    public final void X() {
        O0();
    }

    @Override // androidx.compose.ui.unit.b
    public final float Z() {
        return AbstractC0910f.v(this).r.Z();
    }

    @Override // androidx.compose.ui.unit.b
    public final float a() {
        return AbstractC0910f.v(this).r.a();
    }

    @Override // androidx.compose.ui.node.l0
    public final void t0() {
        O0();
    }
}

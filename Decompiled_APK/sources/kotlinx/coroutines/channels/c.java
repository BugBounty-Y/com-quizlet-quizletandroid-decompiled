package kotlinx.coroutines.channels;

import androidx.glance.appwidget.protobuf.Z;
import com.android.billingclient.api.C1472a;
import java.util.concurrent.atomic.AtomicReferenceFieldUpdater;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C5028l;
import kotlinx.coroutines.E;
import kotlinx.coroutines.J0;

/* loaded from: classes3.dex */
public final class c implements J0 {
    public Object a = j.p;
    public C5028l b;
    public final /* synthetic */ h c;

    public c(h hVar) {
        this.c = hVar;
    }

    @Override // kotlinx.coroutines.J0
    public final void a(kotlinx.coroutines.internal.q qVar, int i) {
        C5028l c5028l = this.b;
        if (c5028l != null) {
            c5028l.a(qVar, i);
        }
    }

    public final Object b(kotlin.coroutines.jvm.internal.c frame) throws Throwable {
        p pVarQ;
        Boolean bool;
        Object obj = this.a;
        boolean z = true;
        if (obj == j.p || obj == j.l) {
            AtomicReferenceFieldUpdater atomicReferenceFieldUpdater = h.g;
            h hVar = this.c;
            p pVar = (p) atomicReferenceFieldUpdater.get(hVar);
            while (true) {
                if (hVar.y()) {
                    this.a = j.l;
                    Throwable thR = hVar.r();
                    if (thR != null) {
                        int i = kotlinx.coroutines.internal.r.a;
                        throw thR;
                    }
                    z = false;
                } else {
                    long andIncrement = h.c.getAndIncrement(hVar);
                    long j = j.b;
                    long j2 = andIncrement / j;
                    int i2 = (int) (andIncrement % j);
                    if (pVar.c != j2) {
                        pVarQ = hVar.q(j2, pVar);
                        if (pVarQ == null) {
                            continue;
                        }
                    } else {
                        pVarQ = pVar;
                    }
                    Object objJ = hVar.J(pVarQ, i2, andIncrement, null);
                    C1472a c1472a = j.m;
                    if (objJ == c1472a) {
                        throw new IllegalStateException("unreachable");
                    }
                    C1472a c1472a2 = j.o;
                    if (objJ == c1472a2) {
                        if (andIncrement < hVar.v()) {
                            pVarQ.a();
                        }
                        pVar = pVarQ;
                    } else {
                        if (objJ == j.n) {
                            h hVar2 = this.c;
                            C5028l c5028lT = E.t(kotlin.coroutines.intrinsics.h.b(frame));
                            try {
                                this.b = c5028lT;
                                Object objJ2 = hVar2.J(pVarQ, i2, andIncrement, this);
                                if (objJ2 == c1472a) {
                                    a(pVarQ, i2);
                                } else {
                                    if (objJ2 == c1472a2) {
                                        if (andIncrement < hVar2.v()) {
                                            pVarQ.a();
                                        }
                                        p pVar2 = (p) h.g.get(hVar2);
                                        while (true) {
                                            if (hVar2.y()) {
                                                C5028l c5028l = this.b;
                                                Intrinsics.d(c5028l);
                                                this.b = null;
                                                this.a = j.l;
                                                Throwable thR2 = hVar.r();
                                                if (thR2 == null) {
                                                    kotlin.p pVar3 = kotlin.r.b;
                                                    c5028l.resumeWith(Boolean.FALSE);
                                                } else {
                                                    kotlin.p pVar4 = kotlin.r.b;
                                                    c5028l.resumeWith(Z.b(thR2));
                                                }
                                            } else {
                                                long andIncrement2 = h.c.getAndIncrement(hVar2);
                                                long j3 = j.b;
                                                long j4 = andIncrement2 / j3;
                                                int i3 = (int) (andIncrement2 % j3);
                                                if (pVar2.c != j4) {
                                                    p pVarQ2 = hVar2.q(j4, pVar2);
                                                    if (pVarQ2 != null) {
                                                        pVar2 = pVarQ2;
                                                    }
                                                }
                                                Object objJ3 = hVar2.J(pVar2, i3, andIncrement2, this);
                                                if (objJ3 == j.m) {
                                                    a(pVar2, i3);
                                                    break;
                                                }
                                                if (objJ3 == j.o) {
                                                    if (andIncrement2 < hVar2.v()) {
                                                        pVar2.a();
                                                    }
                                                } else {
                                                    if (objJ3 == j.n) {
                                                        throw new IllegalStateException("unexpected");
                                                    }
                                                    pVar2.a();
                                                    this.a = objJ3;
                                                    this.b = null;
                                                    bool = Boolean.TRUE;
                                                }
                                            }
                                        }
                                    } else {
                                        pVarQ.a();
                                        this.a = objJ2;
                                        this.b = null;
                                        bool = Boolean.TRUE;
                                    }
                                    c5028lT.m(bool, null);
                                }
                                Object objQ = c5028lT.q();
                                if (objQ == kotlin.coroutines.intrinsics.a.a) {
                                    Intrinsics.checkNotNullParameter(frame, "frame");
                                }
                                return objQ;
                            } catch (Throwable th) {
                                c5028lT.C();
                                throw th;
                            }
                        }
                        pVarQ.a();
                        this.a = objJ;
                    }
                }
            }
        }
        return Boolean.valueOf(z);
    }

    public final Object c() throws Throwable {
        Object obj = this.a;
        C1472a c1472a = j.p;
        if (obj == c1472a) {
            throw new IllegalStateException("`hasNext()` has not been invoked");
        }
        this.a = c1472a;
        if (obj != j.l) {
            return obj;
        }
        Throwable thT = this.c.t();
        int i = kotlinx.coroutines.internal.r.a;
        throw thT;
    }
}

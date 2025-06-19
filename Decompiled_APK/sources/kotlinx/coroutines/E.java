package kotlinx.coroutines;

import com.android.billingclient.api.C1472a;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3397u1;
import com.google.android.gms.internal.mlkit_vision_camera.G1;
import com.google.android.gms.internal.mlkit_vision_camera.H1;
import com.quizlet.ui.compose.C4830x;
import java.util.Iterator;
import java.util.concurrent.CancellationException;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicIntegerFieldUpdater;
import java.util.concurrent.atomic.AtomicReferenceFieldUpdater;
import java.util.concurrent.locks.LockSupport;
import kotlin.C4937f;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.collections.C4927s;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.sequences.Sequence;

/* loaded from: classes3.dex */
public abstract class E {
    public static final C1472a a = new C1472a("RESUME_TOKEN", 2);
    public static final C1472a b = new C1472a("REMOVED_TASK", 2);
    public static final C1472a c = new C1472a("CLOSED_EMPTY", 2);
    public static final C1472a d = new C1472a("COMPLETING_ALREADY", 2);
    public static final C1472a e = new C1472a("COMPLETING_WAITING_CHILDREN", 2);
    public static final C1472a f = new C1472a("COMPLETING_RETRY", 2);
    public static final C1472a g = new C1472a("TOO_LATE_TO_CANCEL", 2);
    public static final C1472a h = new C1472a("SEALED", 2);
    public static final T i = new T(false);
    public static final T j = new T(true);

    public static /* synthetic */ y0 A(C c2, CoroutineContext coroutineContext, D d2, Function2 function2, int i2) {
        if ((i2 & 1) != 0) {
            coroutineContext = kotlin.coroutines.n.a;
        }
        if ((i2 & 2) != 0) {
            d2 = D.a;
        }
        return z(c2, coroutineContext, d2, function2);
    }

    public static final Object B(Object obj) {
        if (obj instanceof C5036u) {
            kotlin.p pVar = kotlin.r.b;
            return androidx.glance.appwidget.protobuf.Z.b(((C5036u) obj).a);
        }
        kotlin.p pVar2 = kotlin.r.b;
        return obj;
    }

    public static final void C(C5028l c5028l, kotlin.coroutines.h hVar, boolean z) {
        Object objF;
        Object obj = C5028l.g.get(c5028l);
        Throwable thE = c5028l.e(obj);
        if (thE != null) {
            kotlin.p pVar = kotlin.r.b;
            objF = androidx.glance.appwidget.protobuf.Z.b(thE);
        } else {
            kotlin.p pVar2 = kotlin.r.b;
            objF = c5028l.f(obj);
        }
        if (!z) {
            hVar.resumeWith(objF);
            return;
        }
        Intrinsics.e(hVar, "null cannot be cast to non-null type kotlinx.coroutines.internal.DispatchedContinuation<T of kotlinx.coroutines.DispatchedTaskKt.resume>");
        kotlinx.coroutines.internal.f fVar = (kotlinx.coroutines.internal.f) hVar;
        kotlin.coroutines.jvm.internal.c cVar = fVar.e;
        CoroutineContext context = cVar.getContext();
        Object objC = kotlinx.coroutines.internal.t.c(context, fVar.g);
        H0 h0C = objC != kotlinx.coroutines.internal.t.a ? AbstractC5038w.c(cVar, context, objC) : null;
        try {
            cVar.resumeWith(objF);
            Unit unit = Unit.a;
            if (h0C == null || h0C.o0()) {
                kotlinx.coroutines.internal.t.a(context, objC);
            }
        } catch (Throwable th) {
            if (h0C == null || h0C.o0()) {
                kotlinx.coroutines.internal.t.a(context, objC);
            }
            throw th;
        }
    }

    public static final Object D(CoroutineContext coroutineContext, Function2 function2) throws Throwable {
        Z zA;
        CoroutineContext coroutineContextA;
        long jO0;
        Thread threadCurrentThread = Thread.currentThread();
        kotlin.coroutines.l lVar = kotlin.coroutines.j.a1;
        kotlin.coroutines.j jVar = (kotlin.coroutines.j) coroutineContext.get(lVar);
        if (jVar == null) {
            zA = C0.a();
            coroutineContextA = AbstractC5038w.a(kotlin.coroutines.n.a, coroutineContext.plus(zA), true);
            kotlinx.coroutines.scheduling.e eVar = O.a;
            if (coroutineContextA != eVar && coroutineContextA.get(lVar) == null) {
                coroutineContextA = coroutineContextA.plus(eVar);
            }
        } else {
            if (jVar instanceof Z) {
            }
            zA = (Z) C0.a.get();
            coroutineContextA = AbstractC5038w.a(kotlin.coroutines.n.a, coroutineContext, true);
            kotlinx.coroutines.scheduling.e eVar2 = O.a;
            if (coroutineContextA != eVar2 && coroutineContextA.get(lVar) == null) {
                coroutineContextA = coroutineContextA.plus(eVar2);
            }
        }
        C5018g c5018g = new C5018g(coroutineContextA, threadCurrentThread, zA);
        c5018g.m0(D.a, c5018g, function2);
        Z z = c5018g.e;
        if (z != null) {
            int i2 = Z.e;
            z.n0(false);
        }
        while (true) {
            if (z != null) {
                try {
                    jO0 = z.o0();
                } catch (Throwable th) {
                    if (z != null) {
                        int i3 = Z.e;
                        z.k0(false);
                    }
                    throw th;
                }
            } else {
                jO0 = Long.MAX_VALUE;
            }
            if (c5018g.d0()) {
                break;
            }
            LockSupport.parkNanos(c5018g, jO0);
            if (Thread.interrupted()) {
                c5018g.x(new InterruptedException());
            }
        }
        if (z != null) {
            int i4 = Z.e;
            z.k0(false);
        }
        Object objI = I(q0.a.get(c5018g));
        C5036u c5036u = objI instanceof C5036u ? (C5036u) objI : null;
        if (c5036u == null) {
            return objI;
        }
        throw c5036u.a;
    }

    public static final Object F(E0 e0, Function2 function2) {
        v(e0, true, new S(q(e0.d.getContext()).i(e0.e, e0, e0.c), 0));
        return H1.c(e0, false, e0, function2);
    }

    public static final String G(kotlin.coroutines.h hVar) {
        Object objB;
        if (hVar instanceof kotlinx.coroutines.internal.f) {
            return ((kotlinx.coroutines.internal.f) hVar).toString();
        }
        try {
            kotlin.p pVar = kotlin.r.b;
            objB = hVar + '@' + r(hVar);
        } catch (Throwable th) {
            kotlin.p pVar2 = kotlin.r.b;
            objB = androidx.glance.appwidget.protobuf.Z.b(th);
        }
        if (kotlin.r.a(objB) != null) {
            objB = hVar.getClass().getName() + '@' + r(hVar);
        }
        return (String) objB;
    }

    public static final long H(long j2) {
        kotlin.time.a aVar = kotlin.time.b.b;
        boolean z = j2 > 0;
        if (z) {
            return kotlin.time.b.e(kotlin.time.b.h(j2, AbstractC3397u1.g(999999L, kotlin.time.d.b)));
        }
        if (z) {
            throw new NoWhenBranchMatchedException();
        }
        return 0L;
    }

    public static final Object I(Object obj) {
        InterfaceC4981e0 interfaceC4981e0;
        C4983f0 c4983f0 = obj instanceof C4983f0 ? (C4983f0) obj : null;
        return (c4983f0 == null || (interfaceC4981e0 = c4983f0.a) == null) ? obj : interfaceC4981e0;
    }

    public static final Object J(CoroutineContext coroutineContext, Function2 function2, kotlin.coroutines.h frame) throws Throwable {
        Object objI;
        CoroutineContext context = frame.getContext();
        CoroutineContext coroutineContextPlus = !((Boolean) coroutineContext.fold(Boolean.FALSE, new C4830x(15, (byte) 0))).booleanValue() ? context.plus(coroutineContext) : AbstractC5038w.a(context, coroutineContext, false);
        o(coroutineContextPlus);
        if (coroutineContextPlus == context) {
            kotlinx.coroutines.internal.p pVar = new kotlinx.coroutines.internal.p(frame, coroutineContextPlus);
            objI = H1.c(pVar, true, pVar, function2);
        } else {
            kotlin.coroutines.i iVar = kotlin.coroutines.j.a1;
            if (Intrinsics.b(coroutineContextPlus.get(iVar), context.get(iVar))) {
                H0 h0 = new H0(frame, coroutineContextPlus);
                CoroutineContext coroutineContext2 = h0.c;
                Object objC = kotlinx.coroutines.internal.t.c(coroutineContext2, null);
                try {
                    Object objC2 = H1.c(h0, true, h0, function2);
                    kotlinx.coroutines.internal.t.a(coroutineContext2, objC);
                    objI = objC2;
                } catch (Throwable th) {
                    kotlinx.coroutines.internal.t.a(coroutineContext2, objC);
                    throw th;
                }
            } else {
                L l = new L(frame, coroutineContextPlus);
                G1.i(function2, l, l);
                while (true) {
                    AtomicIntegerFieldUpdater atomicIntegerFieldUpdater = L.e;
                    int i2 = atomicIntegerFieldUpdater.get(l);
                    if (i2 != 0) {
                        if (i2 != 2) {
                            throw new IllegalStateException("Already suspended");
                        }
                        objI = I(q0.a.get(l));
                        if (objI instanceof C5036u) {
                            throw ((C5036u) objI).a;
                        }
                    } else if (atomicIntegerFieldUpdater.compareAndSet(l, 0, 1)) {
                        objI = kotlin.coroutines.intrinsics.a.a;
                        break;
                    }
                }
            }
        }
        if (objI == kotlin.coroutines.intrinsics.a.a) {
            Intrinsics.checkNotNullParameter(frame, "frame");
        }
        return objI;
    }

    public static final Object K(long j2, Function2 function2, kotlin.coroutines.jvm.internal.c frame) {
        if (j2 <= 0) {
            throw new TimeoutCancellationException("Timed out immediately", null);
        }
        Object objF = F(new E0(j2, frame), function2);
        if (objF == kotlin.coroutines.intrinsics.a.a) {
            Intrinsics.checkNotNullParameter(frame, "frame");
        }
        return objF;
    }

    /* JADX WARN: Removed duplicated region for block: B:37:0x006d A[ORIG_RETURN, RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:39:0x006f  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object L(long r6, kotlin.jvm.functions.Function2 r8, kotlin.coroutines.jvm.internal.c r9) {
        /*
            boolean r0 = r9 instanceof kotlinx.coroutines.F0
            if (r0 == 0) goto L13
            r0 = r9
            kotlinx.coroutines.F0 r0 = (kotlinx.coroutines.F0) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            kotlinx.coroutines.F0 r0 = new kotlinx.coroutines.F0
            r0.<init>(r9)
        L18:
            java.lang.Object r9 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L33
            if (r2 != r3) goto L2b
            kotlin.jvm.internal.J r6 = r0.k
            androidx.glance.appwidget.protobuf.Z.e(r9)     // Catch: kotlinx.coroutines.TimeoutCancellationException -> L29
            return r9
        L29:
            r7 = move-exception
            goto L67
        L2b:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r7 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r7)
            throw r6
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            r4 = 0
            int r9 = (r6 > r4 ? 1 : (r6 == r4 ? 0 : -1))
            if (r9 > 0) goto L3d
            goto L6d
        L3d:
            kotlin.jvm.internal.J r9 = new kotlin.jvm.internal.J
            r9.<init>()
            r0.j = r8     // Catch: kotlinx.coroutines.TimeoutCancellationException -> L65
            r0.k = r9     // Catch: kotlinx.coroutines.TimeoutCancellationException -> L65
            r0.m = r3     // Catch: kotlinx.coroutines.TimeoutCancellationException -> L65
            kotlinx.coroutines.E0 r2 = new kotlinx.coroutines.E0     // Catch: kotlinx.coroutines.TimeoutCancellationException -> L65
            r2.<init>(r6, r0)     // Catch: kotlinx.coroutines.TimeoutCancellationException -> L65
            r9.a = r2     // Catch: kotlinx.coroutines.TimeoutCancellationException -> L65
            java.lang.Object r6 = F(r2, r8)     // Catch: kotlinx.coroutines.TimeoutCancellationException -> L65
            if (r6 != r1) goto L61
            java.lang.String r7 = "frame"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r0, r7)     // Catch: kotlinx.coroutines.TimeoutCancellationException -> L5d
            goto L61
        L5b:
            r7 = r6
            goto L5f
        L5d:
            r6 = move-exception
            goto L5b
        L5f:
            r6 = r9
            goto L67
        L61:
            if (r6 != r1) goto L64
            return r1
        L64:
            return r6
        L65:
            r7 = move-exception
            goto L5f
        L67:
            kotlinx.coroutines.E0 r8 = r7.a
            java.lang.Object r6 = r6.a
            if (r8 != r6) goto L6f
        L6d:
            r6 = 0
            return r6
        L6f:
            throw r7
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlinx.coroutines.E.L(long, kotlin.jvm.functions.Function2, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public static final Object M(kotlin.coroutines.jvm.internal.c frame) {
        Object obj;
        CoroutineContext context = frame.getContext();
        o(context);
        kotlin.coroutines.h hVarB = kotlin.coroutines.intrinsics.h.b(frame);
        kotlinx.coroutines.internal.f fVar = hVarB instanceof kotlinx.coroutines.internal.f ? (kotlinx.coroutines.internal.f) hVarB : null;
        if (fVar == null) {
            obj = Unit.a;
        } else {
            AbstractC5040y abstractC5040y = fVar.d;
            if (kotlinx.coroutines.internal.b.i(abstractC5040y, context)) {
                fVar.f = Unit.a;
                fVar.c = 1;
                abstractC5040y.B(context, fVar);
            } else {
                K0 k0 = new K0(K0.b);
                CoroutineContext coroutineContextPlus = context.plus(k0);
                Unit unit = Unit.a;
                fVar.f = unit;
                fVar.c = 1;
                abstractC5040y.B(coroutineContextPlus, fVar);
                if (k0.a) {
                    Z zA = C0.a();
                    C4927s c4927s = zA.d;
                    if (c4927s != null ? c4927s.isEmpty() : true) {
                        obj = Unit.a;
                    } else {
                        if (zA.b >= 4294967296L) {
                            fVar.f = unit;
                            fVar.c = 1;
                            zA.l0(fVar);
                            obj = kotlin.coroutines.intrinsics.a.a;
                        } else {
                            zA.n0(true);
                            try {
                                fVar.run();
                                do {
                                } while (zA.p0());
                            } finally {
                                try {
                                } finally {
                                }
                            }
                            obj = Unit.a;
                        }
                    }
                }
            }
            obj = kotlin.coroutines.intrinsics.a.a;
        }
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        if (obj == aVar) {
            Intrinsics.checkNotNullParameter(frame, "frame");
        }
        return obj == aVar ? obj : Unit.a;
    }

    public static final CancellationException a(String str, Throwable th) {
        CancellationException cancellationException = new CancellationException(str);
        cancellationException.initCause(th);
        return cancellationException;
    }

    public static r b() {
        r rVar = new r(true);
        rVar.R(null);
        return rVar;
    }

    public static final kotlinx.coroutines.internal.d c(CoroutineContext coroutineContext) {
        if (coroutineContext.get(C5023i0.a) == null) {
            coroutineContext = coroutineContext.plus(d());
        }
        return new kotlinx.coroutines.internal.d(coroutineContext);
    }

    public static C5027k0 d() {
        return new C5027k0(null);
    }

    public static A0 e() {
        return new A0(null);
    }

    public static I f(C c2, CoroutineContext coroutineContext, Function2 function2, int i2) {
        D d2 = D.b;
        if ((i2 & 1) != 0) {
            coroutineContext = kotlin.coroutines.n.a;
        }
        D d3 = (i2 & 2) != 0 ? D.a : d2;
        CoroutineContext coroutineContextB = AbstractC5038w.b(c2, coroutineContext);
        I r0Var = d3 == d2 ? new r0(coroutineContextB, function2) : new I(coroutineContextB, true, true);
        r0Var.m0(d3, r0Var, function2);
        return r0Var;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void g(kotlin.coroutines.jvm.internal.c r4) {
        /*
            boolean r0 = r4 instanceof kotlinx.coroutines.K
            if (r0 == 0) goto L13
            r0 = r4
            kotlinx.coroutines.K r0 = (kotlinx.coroutines.K) r0
            int r1 = r0.k
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.k = r1
            goto L18
        L13:
            kotlinx.coroutines.K r0 = new kotlinx.coroutines.K
            r0.<init>(r4)
        L18:
            java.lang.Object r4 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.k
            r3 = 1
            if (r2 == 0) goto L2f
            if (r2 == r3) goto L2b
            java.lang.IllegalStateException r4 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r4.<init>(r0)
            throw r4
        L2b:
            androidx.glance.appwidget.protobuf.Z.e(r4)
            goto L4e
        L2f:
            androidx.glance.appwidget.protobuf.Z.e(r4)
            r0.k = r3
            kotlinx.coroutines.l r4 = new kotlinx.coroutines.l
            kotlin.coroutines.h r2 = kotlin.coroutines.intrinsics.h.b(r0)
            r4.<init>(r3, r2)
            r4.r()
            java.lang.Object r4 = r4.q()
            if (r4 != r1) goto L4b
            java.lang.String r2 = "frame"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r0, r2)
        L4b:
            if (r4 != r1) goto L4e
            return
        L4e:
            kotlin.KotlinNothingValueException r4 = new kotlin.KotlinNothingValueException
            r4.<init>()
            throw r4
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlinx.coroutines.E.g(kotlin.coroutines.jvm.internal.c):void");
    }

    public static final void h(CoroutineContext coroutineContext, CancellationException cancellationException) {
        InterfaceC5025j0 interfaceC5025j0 = (InterfaceC5025j0) coroutineContext.get(C5023i0.a);
        if (interfaceC5025j0 != null) {
            interfaceC5025j0.j(cancellationException);
        }
    }

    public static final void i(C c2, CancellationException cancellationException) {
        InterfaceC5025j0 interfaceC5025j0 = (InterfaceC5025j0) c2.getCoroutineContext().get(C5023i0.a);
        if (interfaceC5025j0 != null) {
            interfaceC5025j0.j(cancellationException);
        } else {
            throw new IllegalStateException(("Scope cannot be cancelled because it does not have a job: " + c2).toString());
        }
    }

    public static final void j(InterfaceC5025j0 interfaceC5025j0, String str, Throwable th) {
        interfaceC5025j0.j(a(str, th));
    }

    public static final Object k(InterfaceC5025j0 interfaceC5025j0, kotlin.coroutines.jvm.internal.c cVar) {
        interfaceC5025j0.j(null);
        Object objP = interfaceC5025j0.p(cVar);
        return objP == kotlin.coroutines.intrinsics.a.a ? objP : Unit.a;
    }

    public static void l(CoroutineContext coroutineContext) {
        Sequence sequenceD;
        InterfaceC5025j0 interfaceC5025j0 = (InterfaceC5025j0) coroutineContext.get(C5023i0.a);
        if (interfaceC5025j0 == null || (sequenceD = interfaceC5025j0.d()) == null) {
            return;
        }
        Iterator it2 = sequenceD.iterator();
        while (it2.hasNext()) {
            ((InterfaceC5025j0) it2.next()).j(null);
        }
    }

    public static final Object m(Function2 function2, kotlin.coroutines.h frame) {
        kotlinx.coroutines.internal.p pVar = new kotlinx.coroutines.internal.p(frame, frame.getContext());
        Object objC = H1.c(pVar, true, pVar, function2);
        if (objC == kotlin.coroutines.intrinsics.a.a) {
            Intrinsics.checkNotNullParameter(frame, "frame");
        }
        return objC;
    }

    public static final Object n(long j2, kotlin.coroutines.h frame) {
        if (j2 <= 0) {
            return Unit.a;
        }
        C5028l c5028l = new C5028l(1, kotlin.coroutines.intrinsics.h.b(frame));
        c5028l.r();
        if (j2 < Long.MAX_VALUE) {
            q(c5028l.e).f(j2, c5028l);
        }
        Object objQ = c5028l.q();
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        if (objQ == aVar) {
            Intrinsics.checkNotNullParameter(frame, "frame");
        }
        return objQ == aVar ? objQ : Unit.a;
    }

    public static final void o(CoroutineContext coroutineContext) {
        InterfaceC5025j0 interfaceC5025j0 = (InterfaceC5025j0) coroutineContext.get(C5023i0.a);
        if (interfaceC5025j0 != null && !interfaceC5025j0.a()) {
            throw interfaceC5025j0.y();
        }
    }

    public static final AbstractC5040y p(Executor executor) {
        if (executor instanceof N) {
        }
        return new C4975b0(executor);
    }

    public static final J q(CoroutineContext coroutineContext) {
        CoroutineContext.Element element = coroutineContext.get(kotlin.coroutines.j.a1);
        J j2 = element instanceof J ? (J) element : null;
        return j2 == null ? G.a : j2;
    }

    public static final String r(Object obj) {
        return Integer.toHexString(System.identityHashCode(obj));
    }

    public static final InterfaceC5025j0 s(CoroutineContext coroutineContext) {
        InterfaceC5025j0 interfaceC5025j0 = (InterfaceC5025j0) coroutineContext.get(C5023i0.a);
        if (interfaceC5025j0 != null) {
            return interfaceC5025j0;
        }
        throw new IllegalStateException(("Current context doesn't contain Job in it: " + coroutineContext).toString());
    }

    public static final C5028l t(kotlin.coroutines.h hVar) {
        C5028l c5028l;
        C5028l c5028l2;
        if (!(hVar instanceof kotlinx.coroutines.internal.f)) {
            return new C5028l(1, hVar);
        }
        kotlinx.coroutines.internal.f fVar = (kotlinx.coroutines.internal.f) hVar;
        fVar.getClass();
        loop0: while (true) {
            AtomicReferenceFieldUpdater atomicReferenceFieldUpdater = kotlinx.coroutines.internal.f.h;
            Object obj = atomicReferenceFieldUpdater.get(fVar);
            C1472a c1472a = kotlinx.coroutines.internal.b.c;
            c5028l = null;
            if (obj == null) {
                atomicReferenceFieldUpdater.set(fVar, c1472a);
                c5028l2 = null;
                break;
            }
            if (obj instanceof C5028l) {
                while (!atomicReferenceFieldUpdater.compareAndSet(fVar, obj, c1472a)) {
                    if (atomicReferenceFieldUpdater.get(fVar) != obj) {
                        break;
                    }
                }
                c5028l2 = (C5028l) obj;
                break loop0;
            }
            if (obj != c1472a && !(obj instanceof Throwable)) {
                throw new IllegalStateException(("Inconsistent state " + obj).toString());
            }
        }
        if (c5028l2 != null) {
            AtomicReferenceFieldUpdater atomicReferenceFieldUpdater2 = C5028l.g;
            Object obj2 = atomicReferenceFieldUpdater2.get(c5028l2);
            if (!(obj2 instanceof C5035t) || ((C5035t) obj2).d == null) {
                C5028l.f.set(c5028l2, 536870911);
                atomicReferenceFieldUpdater2.set(c5028l2, C4974b.a);
                c5028l = c5028l2;
            } else {
                c5028l2.n();
            }
            if (c5028l != null) {
                return c5028l;
            }
        }
        return new C5028l(2, hVar);
    }

    public static final void u(CoroutineContext coroutineContext, Throwable th) {
        if (th instanceof DispatchException) {
            th = ((DispatchException) th).a;
        }
        try {
            A a2 = (A) coroutineContext.get(C5041z.a);
            if (a2 != null) {
                a2.handleException(coroutineContext, th);
            } else {
                kotlinx.coroutines.internal.b.d(coroutineContext, th);
            }
        } catch (Throwable th2) {
            if (th != th2) {
                RuntimeException runtimeException = new RuntimeException("Exception while trying to handle coroutine exception", th2);
                C4937f.a(runtimeException, th);
                th = runtimeException;
            }
            kotlinx.coroutines.internal.b.d(coroutineContext, th);
        }
    }

    public static final Q v(InterfaceC5025j0 interfaceC5025j0, boolean z, l0 l0Var) {
        if (interfaceC5025j0 instanceof q0) {
            return ((q0) interfaceC5025j0).S(z, l0Var);
        }
        return interfaceC5025j0.q(l0Var.j(), z, new com.quizlet.search.composables.E(1, l0Var, l0.class, "invoke", "invoke(Ljava/lang/Throwable;)V", 0, 13));
    }

    public static final boolean w(CoroutineContext coroutineContext) {
        InterfaceC5025j0 interfaceC5025j0 = (InterfaceC5025j0) coroutineContext.get(C5023i0.a);
        if (interfaceC5025j0 != null) {
            return interfaceC5025j0.a();
        }
        return true;
    }

    public static final boolean x(C c2) {
        InterfaceC5025j0 interfaceC5025j0 = (InterfaceC5025j0) c2.getCoroutineContext().get(C5023i0.a);
        if (interfaceC5025j0 != null) {
            return interfaceC5025j0.a();
        }
        return true;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object y(java.util.List r4, kotlin.coroutines.jvm.internal.c r5) {
        /*
            boolean r0 = r5 instanceof kotlinx.coroutines.C4982f
            if (r0 == 0) goto L13
            r0 = r5
            kotlinx.coroutines.f r0 = (kotlinx.coroutines.C4982f) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            kotlinx.coroutines.f r0 = new kotlinx.coroutines.f
            r0.<init>(r5)
        L18:
            java.lang.Object r5 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L31
            if (r2 != r3) goto L29
            java.util.Iterator r4 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r5)
            goto L38
        L29:
            java.lang.IllegalStateException r4 = new java.lang.IllegalStateException
            java.lang.String r5 = "call to 'resume' before 'invoke' with coroutine"
            r4.<init>(r5)
            throw r4
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r5)
            java.util.Iterator r4 = r4.iterator()
        L38:
            boolean r5 = r4.hasNext()
            if (r5 == 0) goto L4f
            java.lang.Object r5 = r4.next()
            kotlinx.coroutines.j0 r5 = (kotlinx.coroutines.InterfaceC5025j0) r5
            r0.j = r4
            r0.l = r3
            java.lang.Object r5 = r5.p(r0)
            if (r5 != r1) goto L38
            return r1
        L4f:
            kotlin.Unit r4 = kotlin.Unit.a
            return r4
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlinx.coroutines.E.y(java.util.List, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public static final y0 z(C c2, CoroutineContext coroutineContext, D d2, Function2 function2) {
        CoroutineContext coroutineContextB = AbstractC5038w.b(c2, coroutineContext);
        d2.getClass();
        y0 s0Var = d2 == D.b ? new s0(coroutineContextB, function2) : new y0(coroutineContextB, true, true);
        s0Var.m0(d2, s0Var, function2);
        return s0Var;
    }
}

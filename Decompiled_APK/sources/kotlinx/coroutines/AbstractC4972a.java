package kotlinx.coroutines;

import com.google.android.gms.internal.mlkit_vision_camera.G1;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: kotlinx.coroutines.a, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public abstract class AbstractC4972a extends q0 implements kotlin.coroutines.h, C {
    public final CoroutineContext c;

    public AbstractC4972a(CoroutineContext coroutineContext, boolean z, boolean z2) {
        super(z2);
        if (z) {
            R((InterfaceC5025j0) coroutineContext.get(C5023i0.a));
        }
        this.c = coroutineContext.plus(this);
    }

    @Override // kotlinx.coroutines.q0
    public final String B() {
        return getClass().getSimpleName().concat(" was cancelled");
    }

    @Override // kotlinx.coroutines.q0
    public final void O(CompletionHandlerException completionHandlerException) {
        E.u(this.c, completionHandlerException);
    }

    @Override // kotlinx.coroutines.q0
    public final void b0(Object obj) {
        if (!(obj instanceof C5036u)) {
            l0(obj);
        } else {
            C5036u c5036u = (C5036u) obj;
            k0(c5036u.a, C5036u.b.get(c5036u) == 1);
        }
    }

    @Override // kotlin.coroutines.h
    public final CoroutineContext getContext() {
        return this.c;
    }

    @Override // kotlinx.coroutines.C
    public final CoroutineContext getCoroutineContext() {
        return this.c;
    }

    public void k0(Throwable th, boolean z) {
    }

    public void l0(Object obj) {
    }

    public final void m0(D d, AbstractC4972a abstractC4972a, Function2 function2) {
        Object objInvoke;
        int iOrdinal = d.ordinal();
        if (iOrdinal == 0) {
            G1.i(function2, abstractC4972a, this);
            return;
        }
        if (iOrdinal != 1) {
            if (iOrdinal == 2) {
                Intrinsics.checkNotNullParameter(function2, "<this>");
                Intrinsics.checkNotNullParameter(this, "completion");
                kotlin.coroutines.h hVarB = kotlin.coroutines.intrinsics.h.b(kotlin.coroutines.intrinsics.h.a(abstractC4972a, this, function2));
                kotlin.p pVar = kotlin.r.b;
                hVarB.resumeWith(Unit.a);
                return;
            }
            if (iOrdinal != 3) {
                throw new NoWhenBranchMatchedException();
            }
            Intrinsics.checkNotNullParameter(this, "completion");
            try {
                CoroutineContext coroutineContext = this.c;
                Object objC = kotlinx.coroutines.internal.t.c(coroutineContext, null);
                try {
                    Intrinsics.checkNotNullParameter(this, "frame");
                    if (function2 instanceof kotlin.coroutines.jvm.internal.a) {
                        kotlin.jvm.internal.O.d(2, function2);
                        objInvoke = function2.invoke(abstractC4972a, this);
                    } else {
                        objInvoke = kotlin.coroutines.intrinsics.h.c(function2, abstractC4972a, this);
                    }
                    kotlinx.coroutines.internal.t.a(coroutineContext, objC);
                    if (objInvoke != kotlin.coroutines.intrinsics.a.a) {
                        kotlin.p pVar2 = kotlin.r.b;
                        resumeWith(objInvoke);
                    }
                } catch (Throwable th) {
                    kotlinx.coroutines.internal.t.a(coroutineContext, objC);
                    throw th;
                }
            } catch (Throwable th2) {
                th = th2;
                if (th instanceof DispatchException) {
                    th = ((DispatchException) th).a;
                }
                kotlin.p pVar3 = kotlin.r.b;
                resumeWith(androidx.glance.appwidget.protobuf.Z.b(th));
            }
        }
    }

    @Override // kotlin.coroutines.h
    public final void resumeWith(Object obj) {
        Throwable thA = kotlin.r.a(obj);
        if (thA != null) {
            obj = new C5036u(thA, false);
        }
        Object objV = V(obj);
        if (objV == E.e) {
            return;
        }
        v(objV);
    }
}

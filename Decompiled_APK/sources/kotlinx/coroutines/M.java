package kotlinx.coroutines;

import com.google.android.gms.internal.ads.Lv;
import java.util.concurrent.CancellationException;
import kotlin.Unit;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class M extends kotlinx.coroutines.scheduling.i {
    public int c;

    public M(int i) {
        super(0L, false);
        this.c = i;
    }

    public void c(CancellationException cancellationException) {
    }

    public abstract kotlin.coroutines.h d();

    public Throwable e(Object obj) {
        C5036u c5036u = obj instanceof C5036u ? (C5036u) obj : null;
        if (c5036u != null) {
            return c5036u.a;
        }
        return null;
    }

    public Object f(Object obj) {
        return obj;
    }

    public final void g(Throwable th) {
        E.u(d().getContext(), new Lv("Fatal exception in coroutines machinery for " + this + ". Please read KDoc to 'handleFatalException' method and report this incident to maintainers", th));
    }

    public abstract Object h();

    @Override // java.lang.Runnable
    public final void run() {
        try {
            kotlin.coroutines.h hVarD = d();
            Intrinsics.e(hVarD, "null cannot be cast to non-null type kotlinx.coroutines.internal.DispatchedContinuation<T of kotlinx.coroutines.DispatchedTask>");
            kotlinx.coroutines.internal.f fVar = (kotlinx.coroutines.internal.f) hVarD;
            kotlin.coroutines.jvm.internal.c cVar = fVar.e;
            Object obj = fVar.g;
            CoroutineContext context = cVar.getContext();
            Object objC = kotlinx.coroutines.internal.t.c(context, obj);
            InterfaceC5025j0 interfaceC5025j0 = null;
            H0 h0C = objC != kotlinx.coroutines.internal.t.a ? AbstractC5038w.c(cVar, context, objC) : null;
            try {
                CoroutineContext context2 = cVar.getContext();
                Object objH = h();
                Throwable thE = e(objH);
                if (thE == null) {
                    int i = this.c;
                    boolean z = true;
                    if (i != 1 && i != 2) {
                        z = false;
                    }
                    if (z) {
                        interfaceC5025j0 = (InterfaceC5025j0) context2.get(C5023i0.a);
                    }
                }
                if (interfaceC5025j0 != null && !interfaceC5025j0.a()) {
                    CancellationException cancellationExceptionY = interfaceC5025j0.y();
                    c(cancellationExceptionY);
                    kotlin.p pVar = kotlin.r.b;
                    cVar.resumeWith(androidx.glance.appwidget.protobuf.Z.b(cancellationExceptionY));
                } else if (thE != null) {
                    kotlin.p pVar2 = kotlin.r.b;
                    cVar.resumeWith(androidx.glance.appwidget.protobuf.Z.b(thE));
                } else {
                    kotlin.p pVar3 = kotlin.r.b;
                    cVar.resumeWith(f(objH));
                }
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
        } catch (DispatchException e) {
            E.u(d().getContext(), e.a);
        } catch (Throwable th2) {
            g(th2);
        }
    }
}

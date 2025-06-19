package coil3.compose;

import android.os.Trace;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0834w0;
import androidx.compose.runtime.L0;
import androidx.compose.ui.graphics.AbstractC0874w;
import androidx.compose.ui.layout.C0888i;
import androidx.compose.ui.layout.InterfaceC0889j;
import androidx.navigation.C1265a;
import kotlin.Unit;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.AbstractC5040y;
import kotlinx.coroutines.C;
import kotlinx.coroutines.D;
import kotlinx.coroutines.E;
import kotlinx.coroutines.O;
import kotlinx.coroutines.flow.Z;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;
import kotlinx.coroutines.y0;

/* loaded from: classes.dex */
public final class j extends androidx.compose.ui.graphics.painter.b implements InterfaceC0834w0 {
    public static final C1265a v = new C1265a(24);
    public AbstractC0874w h;
    public boolean i;
    public y0 j;
    public C l;
    public Function1 n;
    public m q;
    public c r;
    public final s0 s;
    public final s0 t;
    public final Z u;
    public final InterfaceC0773a0 f = C0776c.z(null);
    public float g = 1.0f;
    public long k = 9205357640488583168L;
    public Function1 m = v;
    public InterfaceC0889j o = C0888i.b;
    public int p = 1;

    public j(c cVar) {
        this.r = cVar;
        this.s = e0.c(cVar);
        s0 s0VarC = e0.c(d.a);
        this.t = s0VarC;
        this.u = new Z(s0VarC);
    }

    public static final coil3.request.g j(j jVar, coil3.request.g gVar, boolean z) {
        jVar.getClass();
        coil3.request.d dVarA = coil3.request.g.a(gVar);
        dVarA.d = new androidx.work.impl.model.l(gVar, false, jVar, 6);
        coil3.request.f fVar = gVar.s;
        if (fVar.g == null) {
            dVarA.l = coil3.size.i.a;
        }
        if (fVar.h == null) {
            InterfaceC0889j interfaceC0889j = jVar.o;
            int i = coil3.compose.internal.g.b;
            dVarA.m = (Intrinsics.b(interfaceC0889j, C0888i.b) || Intrinsics.b(interfaceC0889j, C0888i.e)) ? coil3.size.g.b : coil3.size.g.a;
        }
        if (fVar.i == null) {
            dVarA.n = coil3.size.d.b;
        }
        if (z) {
            kotlin.coroutines.n nVar = kotlin.coroutines.n.a;
            dVarA.f = nVar;
            dVarA.g = nVar;
            dVarA.h = nVar;
        }
        return dVarA.a();
    }

    /* JADX WARN: Removed duplicated region for block: B:11:0x004a  */
    /* JADX WARN: Removed duplicated region for block: B:24:0x0070  */
    /* JADX WARN: Removed duplicated region for block: B:26:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void k(coil3.compose.j r3, coil3.compose.h r4) {
        /*
            kotlinx.coroutines.flow.s0 r0 = r3.t
            java.lang.Object r1 = r0.getValue()
            coil3.compose.h r1 = (coil3.compose.h) r1
            kotlin.jvm.functions.Function1 r2 = r3.m
            java.lang.Object r4 = r2.invoke(r4)
            coil3.compose.h r4 = (coil3.compose.h) r4
            r0.l(r4)
            boolean r0 = r4 instanceof coil3.compose.g
            if (r0 == 0) goto L1d
            r0 = r4
            coil3.compose.g r0 = (coil3.compose.g) r0
            coil3.request.o r0 = r0.b
            goto L26
        L1d:
            boolean r0 = r4 instanceof coil3.compose.e
            if (r0 == 0) goto L35
            r0 = r4
            coil3.compose.e r0 = (coil3.compose.e) r0
            coil3.request.c r0 = r0.b
        L26:
            coil3.request.g r0 = r0.b()
            androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableList.e r2 = coil3.request.i.a
            java.lang.Object r0 = coil3.n.d(r0, r2)
            coil3.transition.a r0 = (coil3.transition.a) r0
            r0.getClass()
        L35:
            androidx.compose.ui.graphics.painter.b r0 = r4.a()
            androidx.compose.runtime.a0 r2 = r3.f
            androidx.compose.runtime.L0 r2 = (androidx.compose.runtime.L0) r2
            r2.setValue(r0)
            androidx.compose.ui.graphics.painter.b r0 = r1.a()
            androidx.compose.ui.graphics.painter.b r2 = r4.a()
            if (r0 == r2) goto L6c
            androidx.compose.ui.graphics.painter.b r0 = r1.a()
            boolean r1 = r0 instanceof androidx.compose.runtime.InterfaceC0834w0
            r2 = 0
            if (r1 == 0) goto L56
            androidx.compose.runtime.w0 r0 = (androidx.compose.runtime.InterfaceC0834w0) r0
            goto L57
        L56:
            r0 = r2
        L57:
            if (r0 == 0) goto L5c
            r0.b()
        L5c:
            androidx.compose.ui.graphics.painter.b r0 = r4.a()
            boolean r1 = r0 instanceof androidx.compose.runtime.InterfaceC0834w0
            if (r1 == 0) goto L67
            r2 = r0
            androidx.compose.runtime.w0 r2 = (androidx.compose.runtime.InterfaceC0834w0) r2
        L67:
            if (r2 == 0) goto L6c
            r2.d()
        L6c:
            kotlin.jvm.functions.Function1 r3 = r3.n
            if (r3 == 0) goto L73
            r3.invoke(r4)
        L73:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: coil3.compose.j.k(coil3.compose.j, coil3.compose.h):void");
    }

    @Override // androidx.compose.runtime.InterfaceC0834w0
    public final void a() {
        y0 y0Var = this.j;
        if (y0Var != null) {
            y0Var.j(null);
        }
        this.j = null;
        Object obj = (androidx.compose.ui.graphics.painter.b) ((L0) this.f).getValue();
        InterfaceC0834w0 interfaceC0834w0 = obj instanceof InterfaceC0834w0 ? (InterfaceC0834w0) obj : null;
        if (interfaceC0834w0 != null) {
            interfaceC0834w0.a();
        }
        this.i = false;
    }

    @Override // androidx.compose.runtime.InterfaceC0834w0
    public final void b() {
        y0 y0Var = this.j;
        if (y0Var != null) {
            y0Var.j(null);
        }
        this.j = null;
        Object obj = (androidx.compose.ui.graphics.painter.b) ((L0) this.f).getValue();
        InterfaceC0834w0 interfaceC0834w0 = obj instanceof InterfaceC0834w0 ? (InterfaceC0834w0) obj : null;
        if (interfaceC0834w0 != null) {
            interfaceC0834w0.b();
        }
        this.i = false;
    }

    @Override // androidx.compose.ui.graphics.painter.b
    public final boolean c(float f) {
        this.g = f;
        return true;
    }

    @Override // androidx.compose.runtime.InterfaceC0834w0
    public final void d() {
        Trace.beginSection("AsyncImagePainter.onRemembered");
        try {
            Object obj = (androidx.compose.ui.graphics.painter.b) ((L0) this.f).getValue();
            InterfaceC0834w0 interfaceC0834w0 = obj instanceof InterfaceC0834w0 ? (InterfaceC0834w0) obj : null;
            if (interfaceC0834w0 != null) {
                interfaceC0834w0.d();
            }
            l();
            this.i = true;
            Unit unit = Unit.a;
            Trace.endSection();
        } catch (Throwable th) {
            Trace.endSection();
            throw th;
        }
    }

    @Override // androidx.compose.ui.graphics.painter.b
    public final boolean e(AbstractC0874w abstractC0874w) {
        this.h = abstractC0874w;
        return true;
    }

    @Override // androidx.compose.ui.graphics.painter.b
    public final long h() {
        androidx.compose.ui.graphics.painter.b bVar = (androidx.compose.ui.graphics.painter.b) ((L0) this.f).getValue();
        if (bVar != null) {
            return bVar.h();
        }
        return 9205357640488583168L;
    }

    @Override // androidx.compose.ui.graphics.painter.b
    public final void i(androidx.compose.ui.graphics.drawscope.d dVar) {
        long jG = dVar.g();
        if (!androidx.compose.ui.geometry.e.a(this.k, jG)) {
            this.k = jG;
        }
        androidx.compose.ui.graphics.painter.b bVar = (androidx.compose.ui.graphics.painter.b) ((L0) this.f).getValue();
        if (bVar != null) {
            bVar.g(dVar, dVar.g(), this.g, this.h);
        }
    }

    public final void l() {
        c cVar = this.r;
        if (cVar == null) {
            return;
        }
        C c = this.l;
        if (c == null) {
            Intrinsics.m("scope");
            throw null;
        }
        i iVar = new i(this, cVar, null);
        CoroutineContext coroutineContext = c.getCoroutineContext();
        int i = coil3.compose.internal.g.b;
        AbstractC5040y abstractC5040y = (AbstractC5040y) coroutineContext.get(AbstractC5040y.a);
        y0 y0VarZ = (abstractC5040y == null || abstractC5040y.equals(O.b)) ? E.z(c, O.b, D.d, iVar) : E.z(E.c(new coil3.compose.internal.c(c.getCoroutineContext())), new coil3.compose.internal.d(abstractC5040y), D.d, iVar);
        y0 y0Var = this.j;
        if (y0Var != null) {
            y0Var.j(null);
        }
        this.j = y0VarZ;
    }

    public final void m(c cVar) {
        if (Intrinsics.b(this.r, cVar)) {
            return;
        }
        this.r = cVar;
        if (cVar == null) {
            y0 y0Var = this.j;
            if (y0Var != null) {
                y0Var.j(null);
            }
            this.j = null;
        } else if (this.i) {
            l();
        }
        if (cVar != null) {
            s0 s0Var = this.s;
            s0Var.getClass();
            s0Var.m(null, cVar);
        }
    }
}

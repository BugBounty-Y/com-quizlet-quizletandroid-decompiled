package androidx.camera.core;

import android.graphics.Matrix;
import android.graphics.Rect;
import android.util.Size;
import androidx.activity.RunnableC0041m;
import androidx.camera.core.impl.A0;
import androidx.camera.core.impl.C0162c;
import androidx.camera.core.impl.C0163c0;
import androidx.camera.core.impl.C0165d0;
import androidx.camera.core.impl.C0168g;
import androidx.camera.core.impl.D0;
import androidx.camera.core.impl.InterfaceC0183w;
import androidx.camera.core.impl.InterfaceC0185y;
import androidx.camera.core.impl.n0;
import androidx.camera.core.impl.z0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

/* loaded from: classes.dex */
public final class X extends l0 {
    public static final V v = new V();
    public static final androidx.camera.core.impl.utils.executor.e w = com.google.android.gms.internal.mlkit_vision_barcode.T.e();
    public W o;
    public androidx.camera.core.impl.utils.executor.e p;
    public androidx.camera.core.impl.m0 q;
    public g0 r;
    public androidx.camera.core.processing.k s;
    public j0 t;
    public n0 u;

    public final void B() {
        n0 n0Var = this.u;
        if (n0Var != null) {
            n0Var.b();
            this.u = null;
        }
        g0 g0Var = this.r;
        if (g0Var != null) {
            g0Var.a();
            this.r = null;
        }
        androidx.camera.core.processing.k kVar = this.s;
        if (kVar != null) {
            kVar.b();
            this.s = null;
        }
        this.t = null;
    }

    public final void C(W w2) {
        com.google.android.gms.internal.mlkit_vision_barcode.S.d();
        if (w2 == null) {
            this.o = null;
            this.c = 2;
            o();
            return;
        }
        this.o = w2;
        this.p = w;
        C0168g c0168g = this.g;
        if ((c0168g != null ? c0168g.a : null) != null) {
            D((C0165d0) this.f, c0168g);
            n();
        }
        m();
    }

    public final void D(C0165d0 c0165d0, C0168g c0168g) {
        com.google.android.gms.internal.mlkit_vision_barcode.S.d();
        InterfaceC0185y interfaceC0185yB = b();
        Objects.requireNonNull(interfaceC0185yB);
        B();
        AbstractC3242q6.h(null, this.s == null);
        Matrix matrix = this.j;
        boolean zL = interfaceC0185yB.l();
        Size size = c0168g.a;
        Rect rect = this.i;
        if (rect == null) {
            rect = size != null ? new Rect(0, 0, size.getWidth(), size.getHeight()) : null;
        }
        Objects.requireNonNull(rect);
        int iG = g(interfaceC0185yB, k(interfaceC0185yB));
        androidx.camera.core.impl.P p = (androidx.camera.core.impl.P) this.f;
        C0162c c0162c = androidx.camera.core.impl.P.f0;
        androidx.camera.core.processing.k kVar = new androidx.camera.core.processing.k(1, 34, c0168g, matrix, zL, rect, iG, ((Integer) p.j(c0162c, -1)).intValue(), interfaceC0185yB.l() && k(interfaceC0185yB));
        this.s = kVar;
        RunnableC0041m runnableC0041m = new RunnableC0041m(this, 10);
        com.google.android.gms.internal.mlkit_vision_barcode.S.d();
        kVar.a();
        kVar.m.add(runnableC0041m);
        j0 j0VarC = this.s.c(interfaceC0185yB, true);
        this.t = j0VarC;
        this.r = j0VarC.k;
        if (this.o != null) {
            InterfaceC0185y interfaceC0185yB2 = b();
            androidx.camera.core.processing.k kVar2 = this.s;
            if (interfaceC0185yB2 != null && kVar2 != null) {
                com.google.android.gms.internal.mlkit_vision_barcode.S.g(new androidx.camera.core.processing.h(kVar2, g(interfaceC0185yB2, k(interfaceC0185yB2)), ((Integer) ((androidx.camera.core.impl.P) this.f).j(c0162c, -1)).intValue()));
            }
            W w2 = this.o;
            w2.getClass();
            j0 j0Var = this.t;
            j0Var.getClass();
            this.p.execute(new androidx.activity.r(12, w2, j0Var));
        }
        androidx.camera.core.impl.m0 m0VarD = androidx.camera.core.impl.m0.d(c0165d0, c0168g.a);
        a0 a0Var = m0VarD.b;
        a0Var.getClass();
        ((androidx.camera.core.impl.X) a0Var.d).m(androidx.camera.core.impl.F.j, c0168g.c);
        int iA = c0165d0.A();
        if (iA != 0) {
            a0Var.getClass();
            if (iA != 0) {
                ((androidx.camera.core.impl.X) a0Var.d).m(A0.w0, Integer.valueOf(iA));
            }
        }
        androidx.camera.camera2.impl.b bVar = c0168g.d;
        if (bVar != null) {
            a0Var.d(bVar);
        }
        if (this.o != null) {
            m0VarD.b(this.r, c0168g.b, ((Integer) ((androidx.camera.core.impl.P) this.f).j(androidx.camera.core.impl.P.g0, -1)).intValue());
        }
        n0 n0Var = this.u;
        if (n0Var != null) {
            n0Var.b();
        }
        n0 n0Var2 = new n0(new androidx.camera.camera2.internal.Z(this, 3));
        this.u = n0Var2;
        m0VarD.f = n0Var2;
        this.q = m0VarD;
        Object[] objArr = {m0VarD.c()};
        ArrayList arrayList = new ArrayList(1);
        Object obj = objArr[0];
        Objects.requireNonNull(obj);
        arrayList.add(obj);
        A(Collections.unmodifiableList(arrayList));
    }

    @Override // androidx.camera.core.l0
    public final A0 e(boolean z, D0 d0) {
        v.getClass();
        C0165d0 c0165d0 = V.a;
        androidx.camera.core.impl.H hA = d0.a(c0165d0.x(), 1);
        if (z) {
            hA = androidx.camera.core.impl.H.z(hA, c0165d0);
        }
        if (hA == null) {
            return null;
        }
        return new C0165d0(C0163c0.a((androidx.camera.core.impl.X) ((com.google.android.gms.internal.instantapps.a) j(hA)).b));
    }

    @Override // androidx.camera.core.l0
    public final Set i() {
        HashSet hashSet = new HashSet();
        hashSet.add(1);
        return hashSet;
    }

    @Override // androidx.camera.core.l0
    public final z0 j(androidx.camera.core.impl.H h) {
        return new com.google.android.gms.internal.instantapps.a(androidx.camera.core.impl.X.k(h));
    }

    @Override // androidx.camera.core.l0
    public final A0 r(InterfaceC0183w interfaceC0183w, z0 z0Var) {
        ((androidx.camera.core.impl.X) z0Var.q()).m(androidx.camera.core.impl.O.b0, 34);
        return z0Var.s();
    }

    public final String toString() {
        return "Preview:".concat(f());
    }

    @Override // androidx.camera.core.l0
    public final C0168g u(androidx.camera.camera2.impl.b bVar) {
        this.q.a(bVar);
        Object[] objArr = {this.q.c()};
        ArrayList arrayList = new ArrayList(1);
        Object obj = objArr[0];
        Objects.requireNonNull(obj);
        arrayList.add(obj);
        A(Collections.unmodifiableList(arrayList));
        com.quizlet.data.interactor.folderwithcreator.m mVarA = this.g.a();
        mVarA.d = bVar;
        return mVarA.d();
    }

    @Override // androidx.camera.core.l0
    public final C0168g v(C0168g c0168g, C0168g c0168g2) {
        D((C0165d0) this.f, c0168g);
        return c0168g;
    }

    @Override // androidx.camera.core.l0
    public final void w() {
        B();
    }

    @Override // androidx.camera.core.l0
    public final void y(Rect rect) {
        this.i = rect;
        InterfaceC0185y interfaceC0185yB = b();
        androidx.camera.core.processing.k kVar = this.s;
        if (interfaceC0185yB == null || kVar == null) {
            return;
        }
        com.google.android.gms.internal.mlkit_vision_barcode.S.g(new androidx.camera.core.processing.h(kVar, g(interfaceC0185yB, k(interfaceC0185yB)), ((Integer) ((androidx.camera.core.impl.P) this.f).j(androidx.camera.core.impl.P.f0, -1)).intValue()));
    }
}

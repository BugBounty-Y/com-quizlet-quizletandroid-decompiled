package androidx.camera.core;

import android.graphics.Matrix;
import android.graphics.Rect;
import androidx.camera.core.impl.A0;
import androidx.camera.core.impl.C0163c0;
import androidx.camera.core.impl.C0168g;
import androidx.camera.core.impl.D0;
import androidx.camera.core.impl.InterfaceC0183w;
import androidx.camera.core.impl.n0;
import androidx.camera.core.impl.z0;
import androidx.camera.core.internal.compat.quirk.OnePixelShiftQuirk;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Objects;
import java.util.concurrent.Executor;

/* loaded from: classes.dex */
public final class A extends l0 {
    public static final C0201y u = new C0201y();
    public final D o;
    public final Object p;
    public com.google.firebase.messaging.p q;
    public androidx.camera.core.impl.m0 r;
    public g0 s;
    public n0 t;

    public A(androidx.camera.core.impl.M m) {
        super(m);
        this.p = new Object();
        if (((Integer) ((androidx.camera.core.impl.M) this.f).j(androidx.camera.core.impl.M.b, 0)).intValue() == 1) {
            this.o = new E();
        } else {
            this.o = new H((Executor) m.j(androidx.camera.core.internal.l.B0, com.google.android.gms.internal.mlkit_vision_barcode.T.c()));
        }
        this.o.d = C();
        this.o.e = ((Boolean) ((androidx.camera.core.impl.M) this.f).j(androidx.camera.core.impl.M.g, Boolean.FALSE)).booleanValue();
    }

    /* JADX WARN: Removed duplicated region for block: B:15:0x008b  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final androidx.camera.core.impl.m0 B(androidx.camera.core.impl.M r14, androidx.camera.core.impl.C0168g r15) {
        /*
            Method dump skipped, instructions count: 399
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.camera.core.A.B(androidx.camera.core.impl.M, androidx.camera.core.impl.g):androidx.camera.core.impl.m0");
    }

    public final int C() {
        return ((Integer) ((androidx.camera.core.impl.M) this.f).j(androidx.camera.core.impl.M.e, 1)).intValue();
    }

    @Override // androidx.camera.core.l0
    public final A0 e(boolean z, D0 d0) {
        u.getClass();
        androidx.camera.core.impl.M m = C0201y.a;
        androidx.camera.core.impl.H hA = d0.a(m.x(), 1);
        if (z) {
            hA = androidx.camera.core.impl.H.z(hA, m);
        }
        if (hA == null) {
            return null;
        }
        return new androidx.camera.core.impl.M(C0163c0.a(((androidx.camera.camera2.impl.a) j(hA)).b));
    }

    @Override // androidx.camera.core.l0
    public final z0 j(androidx.camera.core.impl.H h) {
        return new androidx.camera.camera2.impl.a(androidx.camera.core.impl.X.k(h));
    }

    @Override // androidx.camera.core.l0
    public final void p() {
        this.o.s = true;
    }

    @Override // androidx.camera.core.l0
    public final A0 r(InterfaceC0183w interfaceC0183w, z0 z0Var) {
        Boolean bool = (Boolean) ((androidx.camera.core.impl.M) this.f).j(androidx.camera.core.impl.M.f, null);
        boolean zA = interfaceC0183w.h().a(OnePixelShiftQuirk.class);
        D d = this.o;
        if (bool != null) {
            zA = bool.booleanValue();
        }
        d.f = zA;
        synchronized (this.p) {
        }
        return z0Var.s();
    }

    public final String toString() {
        return "ImageAnalysis:".concat(f());
    }

    @Override // androidx.camera.core.l0
    public final C0168g u(androidx.camera.camera2.impl.b bVar) {
        this.r.a(bVar);
        Object[] objArr = {this.r.c()};
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
        androidx.camera.core.impl.M m = (androidx.camera.core.impl.M) this.f;
        d();
        androidx.camera.core.impl.m0 m0VarB = B(m, c0168g);
        this.r = m0VarB;
        Object[] objArr = {m0VarB.c()};
        ArrayList arrayList = new ArrayList(1);
        Object obj = objArr[0];
        Objects.requireNonNull(obj);
        arrayList.add(obj);
        A(Collections.unmodifiableList(arrayList));
        return c0168g;
    }

    @Override // androidx.camera.core.l0
    public final void w() {
        com.google.android.gms.internal.mlkit_vision_barcode.S.d();
        n0 n0Var = this.t;
        if (n0Var != null) {
            n0Var.b();
            this.t = null;
        }
        g0 g0Var = this.s;
        if (g0Var != null) {
            g0Var.a();
            this.s = null;
        }
        D d = this.o;
        d.s = false;
        d.c();
    }

    @Override // androidx.camera.core.l0
    public final void x(Matrix matrix) {
        super.x(matrix);
        D d = this.o;
        synchronized (d.r) {
            d.l = matrix;
            d.m = new Matrix(d.l);
        }
    }

    @Override // androidx.camera.core.l0
    public final void y(Rect rect) {
        this.i = rect;
        D d = this.o;
        synchronized (d.r) {
            d.j = rect;
            d.k = new Rect(d.j);
        }
    }
}

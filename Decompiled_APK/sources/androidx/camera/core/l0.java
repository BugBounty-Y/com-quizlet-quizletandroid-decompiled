package androidx.camera.core;

import android.graphics.Matrix;
import android.graphics.Rect;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.camera.core.impl.A0;
import androidx.camera.core.impl.C0162c;
import androidx.camera.core.impl.C0168g;
import androidx.camera.core.impl.D0;
import androidx.camera.core.impl.InterfaceC0182v;
import androidx.camera.core.impl.InterfaceC0183w;
import androidx.camera.core.impl.InterfaceC0185y;
import androidx.camera.core.impl.q0;
import androidx.camera.core.impl.z0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;
import com.j256.ormlite.stmt.query.SimpleComparison;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;

/* loaded from: classes.dex */
public abstract class l0 {
    public A0 d;
    public final Object e;
    public A0 f;
    public C0168g g;
    public A0 h;
    public Rect i;
    public InterfaceC0185y k;
    public InterfaceC0185y l;
    public final HashSet a = new HashSet();
    public final Object b = new Object();
    public int c = 2;
    public Matrix j = new Matrix();
    public q0 m = q0.a();
    public q0 n = q0.a();

    public l0(A0 a0) {
        this.e = a0;
        this.f = a0;
    }

    public final void A(List list) {
        if (list.isEmpty()) {
            return;
        }
        this.m = (q0) list.get(0);
        if (list.size() > 1) {
            this.n = (q0) list.get(1);
        }
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            for (androidx.camera.core.impl.J j : ((q0) it2.next()).b()) {
                if (j.j == null) {
                    j.j = getClass();
                }
            }
        }
    }

    public final void a(InterfaceC0185y interfaceC0185y, InterfaceC0185y interfaceC0185y2, A0 a0, A0 a02) {
        synchronized (this.b) {
            this.k = interfaceC0185y;
            this.l = interfaceC0185y2;
            this.a.add(interfaceC0185y);
            if (interfaceC0185y2 != null) {
                this.a.add(interfaceC0185y2);
            }
        }
        this.d = a0;
        this.h = a02;
        this.f = l(interfaceC0185y.n(), this.d, this.h);
        p();
    }

    public final InterfaceC0185y b() {
        InterfaceC0185y interfaceC0185y;
        synchronized (this.b) {
            interfaceC0185y = this.k;
        }
        return interfaceC0185y;
    }

    public final InterfaceC0182v c() {
        synchronized (this.b) {
            try {
                InterfaceC0185y interfaceC0185y = this.k;
                if (interfaceC0185y == null) {
                    return InterfaceC0182v.a;
                }
                return interfaceC0185y.g();
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public final String d() {
        InterfaceC0185y interfaceC0185yB = b();
        AbstractC3242q6.g(interfaceC0185yB, "No camera attached to use case: " + this);
        return interfaceC0185yB.n().c();
    }

    public abstract A0 e(boolean z, D0 d0);

    public final String f() {
        String str = (String) this.f.j(androidx.camera.core.internal.k.z0, "<UnknownUseCase-" + hashCode() + SimpleComparison.GREATER_THAN_OPERATION);
        Objects.requireNonNull(str);
        return str;
    }

    public final int g(InterfaceC0185y interfaceC0185y, boolean z) {
        int iG = interfaceC0185y.n().g(((androidx.camera.core.impl.P) this.f).v());
        return (interfaceC0185y.l() || !z) ? iG : androidx.camera.core.impl.utils.f.f(-iG);
    }

    public final InterfaceC0185y h() {
        InterfaceC0185y interfaceC0185y;
        synchronized (this.b) {
            interfaceC0185y = this.l;
        }
        return interfaceC0185y;
    }

    public Set i() {
        return Collections.EMPTY_SET;
    }

    public abstract z0 j(androidx.camera.core.impl.H h);

    public final boolean k(InterfaceC0185y interfaceC0185y) {
        int iIntValue = ((Integer) ((androidx.camera.core.impl.P) this.f).j(androidx.camera.core.impl.P.g0, -1)).intValue();
        if (iIntValue == -1 || iIntValue == 0) {
            return false;
        }
        if (iIntValue == 1) {
            return true;
        }
        if (iIntValue == 2) {
            return interfaceC0185y.n().e() == 0;
        }
        throw new AssertionError(android.support.v4.media.session.a.f(iIntValue, "Unknown mirrorMode: "));
    }

    /* JADX WARN: Type inference failed for: r1v0, types: [androidx.camera.core.impl.H, androidx.camera.core.impl.j0, java.lang.Object] */
    public final A0 l(InterfaceC0183w interfaceC0183w, A0 a0, A0 a02) {
        androidx.camera.core.impl.X xB;
        if (a02 != null) {
            xB = androidx.camera.core.impl.X.k(a02);
            xB.a.remove(androidx.camera.core.internal.k.z0);
        } else {
            xB = androidx.camera.core.impl.X.b();
        }
        C0162c c0162c = androidx.camera.core.impl.P.d0;
        ?? r1 = this.e;
        boolean zC = r1.c(c0162c);
        TreeMap treeMap = xB.a;
        if (zC || r1.c(androidx.camera.core.impl.P.h0)) {
            C0162c c0162c2 = androidx.camera.core.impl.P.l0;
            if (treeMap.containsKey(c0162c2)) {
                treeMap.remove(c0162c2);
            }
        }
        C0162c c0162c3 = androidx.camera.core.impl.P.l0;
        if (r1.c(c0162c3)) {
            C0162c c0162c4 = androidx.camera.core.impl.P.j0;
            if (treeMap.containsKey(c0162c4) && ((androidx.camera.core.resolutionselector.b) r1.e(c0162c3)).b != null) {
                treeMap.remove(c0162c4);
            }
        }
        Iterator it2 = r1.f().iterator();
        while (it2.hasNext()) {
            androidx.camera.core.impl.H.t(xB, xB, r1, (C0162c) it2.next());
        }
        if (a0 != null) {
            for (C0162c c0162c5 : a0.f()) {
                if (!c0162c5.a.equals(androidx.camera.core.internal.k.z0.a)) {
                    androidx.camera.core.impl.H.t(xB, xB, a0, c0162c5);
                }
            }
        }
        if (treeMap.containsKey(androidx.camera.core.impl.P.h0)) {
            C0162c c0162c6 = androidx.camera.core.impl.P.d0;
            if (treeMap.containsKey(c0162c6)) {
                treeMap.remove(c0162c6);
            }
        }
        C0162c c0162c7 = androidx.camera.core.impl.P.l0;
        if (treeMap.containsKey(c0162c7)) {
            ((androidx.camera.core.resolutionselector.b) xB.e(c0162c7)).getClass();
        }
        return r(interfaceC0183w, j(xB));
    }

    public final void m() {
        this.c = 1;
        o();
    }

    public final void n() {
        Iterator it2 = this.a.iterator();
        while (it2.hasNext()) {
            ((k0) it2.next()).d(this);
        }
    }

    public final void o() {
        int iK = AbstractC0147y.k(this.c);
        HashSet hashSet = this.a;
        if (iK == 0) {
            Iterator it2 = hashSet.iterator();
            while (it2.hasNext()) {
                ((k0) it2.next()).c(this);
            }
        } else {
            if (iK != 1) {
                return;
            }
            Iterator it3 = hashSet.iterator();
            while (it3.hasNext()) {
                ((k0) it3.next()).o(this);
            }
        }
    }

    public void p() {
    }

    public void q() {
    }

    public abstract A0 r(InterfaceC0183w interfaceC0183w, z0 z0Var);

    public void s() {
    }

    public void t() {
    }

    public abstract C0168g u(androidx.camera.camera2.impl.b bVar);

    public abstract C0168g v(C0168g c0168g, C0168g c0168g2);

    public abstract void w();

    public void x(Matrix matrix) {
        this.j = new Matrix(matrix);
    }

    public void y(Rect rect) {
        this.i = rect;
    }

    /* JADX WARN: Type inference failed for: r5v2, types: [androidx.camera.core.impl.A0, java.lang.Object] */
    public final void z(InterfaceC0185y interfaceC0185y) {
        w();
        synchronized (this.b) {
            try {
                InterfaceC0185y interfaceC0185y2 = this.k;
                if (interfaceC0185y == interfaceC0185y2) {
                    this.a.remove(interfaceC0185y2);
                    this.k = null;
                }
                InterfaceC0185y interfaceC0185y3 = this.l;
                if (interfaceC0185y == interfaceC0185y3) {
                    this.a.remove(interfaceC0185y3);
                    this.l = null;
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        this.g = null;
        this.i = null;
        this.f = this.e;
        this.d = null;
        this.h = null;
    }
}

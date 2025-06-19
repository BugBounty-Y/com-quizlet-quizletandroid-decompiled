package androidx.camera.core;

import android.util.Log;
import android.util.Pair;
import android.util.Size;
import androidx.camera.core.impl.A0;
import androidx.camera.core.impl.C0162c;
import androidx.camera.core.impl.C0163c0;
import androidx.camera.core.impl.C0166e;
import androidx.camera.core.impl.C0168g;
import androidx.camera.core.impl.D0;
import androidx.camera.core.impl.InterfaceC0183w;
import androidx.camera.core.impl.InterfaceC0185y;
import androidx.camera.core.impl.n0;
import androidx.camera.core.impl.z0;
import androidx.camera.core.internal.compat.quirk.SoftwareJpegEncodingPreferredQuirk;
import com.google.android.gms.ads.internal.client.C1608n;
import com.google.android.gms.internal.ads.C1721Kc;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes.dex */
public final class L extends l0 {
    public static final I x = new I();
    public final int o;
    public final AtomicReference p;
    public final int q;
    public final androidx.camera.core.internal.i r;
    public androidx.camera.core.impl.m0 s;
    public C1721Kc t;
    public androidx.camera.core.imagecapture.d u;
    public n0 v;
    public final Q w;

    public L(androidx.camera.core.impl.N n) {
        super(n);
        this.p = new AtomicReference(null);
        this.q = -1;
        this.w = new Q();
        androidx.camera.core.impl.N n2 = (androidx.camera.core.impl.N) this.f;
        C0162c c0162c = androidx.camera.core.impl.N.b;
        if (n2.c(c0162c)) {
            this.o = ((Integer) n2.e(c0162c)).intValue();
        } else {
            this.o = 1;
        }
        ((Integer) n2.j(androidx.camera.core.impl.N.h, 0)).getClass();
        this.r = new androidx.camera.core.internal.i((J) n2.j(androidx.camera.core.impl.N.i, null));
    }

    public static boolean E(int i, List list) {
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            if (((Integer) ((Pair) it2.next()).first).equals(Integer.valueOf(i))) {
                return true;
            }
        }
        return false;
    }

    public final void B(boolean z) {
        androidx.camera.core.imagecapture.d dVar;
        com.google.android.gms.internal.mlkit_vision_barcode.S.d();
        n0 n0Var = this.v;
        if (n0Var != null) {
            n0Var.b();
            this.v = null;
        }
        C1721Kc c1721Kc = this.t;
        if (c1721Kc != null) {
            c1721Kc.e();
            this.t = null;
        }
        if (z || (dVar = this.u) == null) {
            return;
        }
        dVar.b();
        this.u = null;
    }

    public final androidx.camera.core.impl.m0 C(String str, androidx.camera.core.impl.N n, C0168g c0168g) {
        com.google.android.gms.internal.mlkit_vision_barcode.S.d();
        Objects.toString(c0168g);
        Size size = c0168g.a;
        InterfaceC0185y interfaceC0185yB = b();
        Objects.requireNonNull(interfaceC0185yB);
        boolean z = !interfaceC0185yB.l();
        if (this.t != null) {
            AbstractC3242q6.h(null, z);
            this.t.e();
        }
        if (((Boolean) this.f.j(androidx.camera.core.impl.N.j, Boolean.FALSE)).booleanValue()) {
            b().h().y();
        }
        this.t = new C1721Kc(n, size, z);
        if (this.u == null) {
            this.u = new androidx.camera.core.imagecapture.d(this.w);
        }
        androidx.camera.core.imagecapture.d dVar = this.u;
        C1721Kc c1721Kc = this.t;
        dVar.getClass();
        com.google.android.gms.internal.mlkit_vision_barcode.S.d();
        dVar.b = c1721Kc;
        c1721Kc.getClass();
        com.google.android.gms.internal.mlkit_vision_barcode.S.d();
        androidx.work.impl.model.v vVar = (androidx.work.impl.model.v) c1721Kc.c;
        vVar.getClass();
        com.google.android.gms.internal.mlkit_vision_barcode.S.d();
        AbstractC3242q6.h("The ImageReader is not initialized.", ((a0) vVar.b) != null);
        a0 a0Var = (a0) vVar.b;
        synchronized (a0Var.c) {
            a0Var.f = dVar;
        }
        C1721Kc c1721Kc2 = this.t;
        androidx.camera.core.impl.m0 m0VarD = androidx.camera.core.impl.m0.d((androidx.camera.core.impl.N) c1721Kc2.b, c0168g.a);
        androidx.camera.core.imagecapture.a aVar = (androidx.camera.core.imagecapture.a) c1721Kc2.e;
        g0 g0Var = aVar.a;
        Objects.requireNonNull(g0Var);
        C0196t c0196t = C0196t.d;
        C1608n c1608nA = C0166e.a(g0Var);
        c1608nA.e = c0196t;
        m0VarD.a.add(c1608nA.i());
        g0 g0Var2 = aVar.b;
        if (g0Var2 != null) {
            m0VarD.h = C0166e.a(g0Var2).i();
        }
        if (this.o == 2 && !c0168g.e) {
            c().d(m0VarD);
        }
        androidx.camera.camera2.impl.b bVar = c0168g.d;
        if (bVar != null) {
            m0VarD.b.d(bVar);
        }
        n0 n0Var = this.v;
        if (n0Var != null) {
            n0Var.b();
        }
        n0 n0Var2 = new n0(new androidx.camera.camera2.internal.Z(this, 2));
        this.v = n0Var2;
        m0VarD.f = n0Var2;
        return m0VarD;
    }

    public final int D() {
        int iIntValue;
        synchronized (this.p) {
            iIntValue = this.q;
            if (iIntValue == -1) {
                iIntValue = ((Integer) ((androidx.camera.core.impl.N) this.f).j(androidx.camera.core.impl.N.c, 2)).intValue();
            }
        }
        return iIntValue;
    }

    @Override // androidx.camera.core.l0
    public final A0 e(boolean z, D0 d0) {
        x.getClass();
        androidx.camera.core.impl.N n = I.a;
        androidx.camera.core.impl.H hA = d0.a(n.x(), this.o);
        if (z) {
            hA = androidx.camera.core.impl.H.z(hA, n);
        }
        if (hA == null) {
            return null;
        }
        return new androidx.camera.core.impl.N(C0163c0.a((androidx.camera.core.impl.X) ((com.google.android.gms.auth.api.signin.internal.h) j(hA)).b));
    }

    @Override // androidx.camera.core.l0
    public final Set i() {
        HashSet hashSet = new HashSet();
        hashSet.add(4);
        return hashSet;
    }

    @Override // androidx.camera.core.l0
    public final z0 j(androidx.camera.core.impl.H h) {
        return new com.google.android.gms.auth.api.signin.internal.h(androidx.camera.core.impl.X.k(h));
    }

    @Override // androidx.camera.core.l0
    public final void p() {
        AbstractC3242q6.g(b(), "Attached camera cannot be null");
        if (D() == 3) {
            InterfaceC0185y interfaceC0185yB = b();
            if ((interfaceC0185yB != null ? interfaceC0185yB.n().e() : -1) != 0) {
                throw new IllegalArgumentException("Not a front camera despite setting FLASH_MODE_SCREEN in ImageCapture");
            }
        }
    }

    @Override // androidx.camera.core.l0
    public final void q() {
        AbstractC3053s1.f(3, "ImageCapture");
        synchronized (this.p) {
            try {
                if (this.p.get() == null) {
                    c().c(D());
                }
            } finally {
            }
        }
        c().f(this.r);
    }

    @Override // androidx.camera.core.l0
    public final A0 r(InterfaceC0183w interfaceC0183w, z0 z0Var) {
        Object objE;
        Object objE2;
        Object objE3;
        if (interfaceC0183w.h().a(SoftwareJpegEncodingPreferredQuirk.class)) {
            Boolean bool = Boolean.FALSE;
            androidx.camera.core.impl.H hQ = z0Var.q();
            C0162c c0162c = androidx.camera.core.impl.N.g;
            Object objE4 = Boolean.TRUE;
            C0163c0 c0163c0 = (C0163c0) hQ;
            c0163c0.getClass();
            try {
                objE4 = c0163c0.e(c0162c);
            } catch (IllegalArgumentException unused) {
            }
            if (bool.equals(objE4)) {
                AbstractC3053s1.h("ImageCapture", "Device quirk suggests software JPEG encoder, but it has been explicitly disabled.");
            } else {
                if (AbstractC3053s1.f(4, "ImageCapture")) {
                    Log.i("ImageCapture", "Requesting software JPEG due to device quirk.");
                }
                ((androidx.camera.core.impl.X) z0Var.q()).m(androidx.camera.core.impl.N.g, Boolean.TRUE);
            }
        }
        androidx.camera.core.impl.H hQ2 = z0Var.q();
        Boolean bool2 = Boolean.TRUE;
        C0162c c0162c2 = androidx.camera.core.impl.N.g;
        Object objE5 = Boolean.FALSE;
        C0163c0 c0163c02 = (C0163c0) hQ2;
        c0163c02.getClass();
        try {
            objE5 = c0163c02.e(c0162c2);
        } catch (IllegalArgumentException unused2) {
        }
        boolean zEquals = bool2.equals(objE5);
        Object objE6 = null;
        boolean z = false;
        if (zEquals) {
            if (b() != null) {
                b().h().y();
            }
            try {
                objE3 = c0163c02.e(androidx.camera.core.impl.N.d);
            } catch (IllegalArgumentException unused3) {
                objE3 = null;
            }
            Integer num = (Integer) objE3;
            if (num == null || num.intValue() == 256) {
                z = true;
            } else {
                AbstractC3053s1.h("ImageCapture", "Software JPEG cannot be used with non-JPEG output buffer format.");
            }
            if (!z) {
                AbstractC3053s1.h("ImageCapture", "Unable to support software JPEG. Disabling.");
                ((androidx.camera.core.impl.X) hQ2).m(androidx.camera.core.impl.N.g, Boolean.FALSE);
            }
        }
        androidx.camera.core.impl.H hQ3 = z0Var.q();
        C0162c c0162c3 = androidx.camera.core.impl.N.d;
        C0163c0 c0163c03 = (C0163c0) hQ3;
        c0163c03.getClass();
        try {
            objE = c0163c03.e(c0162c3);
        } catch (IllegalArgumentException unused4) {
            objE = null;
        }
        Integer num2 = (Integer) objE;
        if (num2 != null) {
            if (b() != null) {
                b().h().y();
            }
            ((androidx.camera.core.impl.X) z0Var.q()).m(androidx.camera.core.impl.O.b0, Integer.valueOf(z ? 35 : num2.intValue()));
        } else {
            androidx.camera.core.impl.H hQ4 = z0Var.q();
            C0162c c0162c4 = androidx.camera.core.impl.N.e;
            C0163c0 c0163c04 = (C0163c0) hQ4;
            c0163c04.getClass();
            try {
                objE2 = c0163c04.e(c0162c4);
            } catch (IllegalArgumentException unused5) {
                objE2 = null;
            }
            if (Objects.equals(objE2, 1)) {
                ((androidx.camera.core.impl.X) z0Var.q()).m(androidx.camera.core.impl.O.b0, 4101);
                ((androidx.camera.core.impl.X) z0Var.q()).m(androidx.camera.core.impl.O.c0, C0196t.c);
            } else if (z) {
                ((androidx.camera.core.impl.X) z0Var.q()).m(androidx.camera.core.impl.O.b0, 35);
            } else {
                androidx.camera.core.impl.H hQ5 = z0Var.q();
                C0162c c0162c5 = androidx.camera.core.impl.P.k0;
                C0163c0 c0163c05 = (C0163c0) hQ5;
                c0163c05.getClass();
                try {
                    objE6 = c0163c05.e(c0162c5);
                } catch (IllegalArgumentException unused6) {
                }
                List list = (List) objE6;
                if (list == null) {
                    ((androidx.camera.core.impl.X) z0Var.q()).m(androidx.camera.core.impl.O.b0, 256);
                } else if (E(256, list)) {
                    ((androidx.camera.core.impl.X) z0Var.q()).m(androidx.camera.core.impl.O.b0, 256);
                } else if (E(35, list)) {
                    ((androidx.camera.core.impl.X) z0Var.q()).m(androidx.camera.core.impl.O.b0, 35);
                }
            }
        }
        return z0Var.s();
    }

    @Override // androidx.camera.core.l0
    public final void t() {
        androidx.camera.core.internal.i iVar = this.r;
        iVar.b();
        iVar.a();
        androidx.camera.core.imagecapture.d dVar = this.u;
        if (dVar != null) {
            dVar.b();
        }
    }

    public final String toString() {
        return "ImageCapture:".concat(f());
    }

    @Override // androidx.camera.core.l0
    public final C0168g u(androidx.camera.camera2.impl.b bVar) {
        this.s.a(bVar);
        Object[] objArr = {this.s.c()};
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
        androidx.camera.core.impl.m0 m0VarC = C(d(), (androidx.camera.core.impl.N) this.f, c0168g);
        this.s = m0VarC;
        Object[] objArr = {m0VarC.c()};
        ArrayList arrayList = new ArrayList(1);
        Object obj = objArr[0];
        Objects.requireNonNull(obj);
        arrayList.add(obj);
        A(Collections.unmodifiableList(arrayList));
        m();
        return c0168g;
    }

    @Override // androidx.camera.core.l0
    public final void w() {
        androidx.camera.core.internal.i iVar = this.r;
        iVar.b();
        iVar.a();
        androidx.camera.core.imagecapture.d dVar = this.u;
        if (dVar != null) {
            dVar.b();
        }
        B(false);
        c().f(null);
    }
}

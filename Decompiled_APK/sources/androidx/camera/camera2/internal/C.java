package androidx.camera.camera2.internal;

import android.content.Context;
import android.hardware.camera2.CameraDevice;
import android.os.Handler;
import android.text.TextUtils;
import android.util.Range;
import android.util.Rational;
import android.util.Size;
import androidx.activity.RunnableC0041m;
import androidx.camera.camera2.internal.compat.CameraAccessExceptionCompat;
import androidx.camera.camera2.internal.compat.quirk.LegacyCameraOutputConfigNullPointerQuirk;
import androidx.camera.camera2.internal.compat.quirk.LegacyCameraSurfaceCleanupQuirk;
import androidx.camera.core.C0153e;
import androidx.camera.core.CameraUnavailableException;
import androidx.camera.core.impl.A0;
import androidx.camera.core.impl.AbstractC0171j;
import androidx.camera.core.impl.AbstractC0180t;
import androidx.camera.core.impl.C0;
import androidx.camera.core.impl.C0158a;
import androidx.camera.core.impl.C0162c;
import androidx.camera.core.impl.C0163c0;
import androidx.camera.core.impl.C0168g;
import androidx.camera.core.impl.C0169h;
import androidx.camera.core.impl.C0179s;
import androidx.camera.core.impl.EnumC0184x;
import androidx.camera.core.impl.InterfaceC0161b0;
import androidx.camera.core.impl.InterfaceC0178q;
import androidx.camera.core.impl.InterfaceC0182v;
import androidx.camera.core.impl.InterfaceC0183w;
import androidx.camera.core.impl.InterfaceC0185y;
import androidx.camera.core.impl.x0;
import androidx.camera.core.impl.y0;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;
import com.google.android.gms.internal.mlkit_vision_barcode.Y5;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.Executor;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.atomic.AtomicInteger;

/* loaded from: classes.dex */
public final class C implements InterfaceC0185y {
    public InterfaceC0178q A;
    public final Object B;
    public boolean C;
    public final W D;
    public final com.google.firebase.platforminfo.c E;
    public final f0 F;
    public final com.quizlet.data.interactor.school.b G;
    public volatile int H = 3;
    public final y0 a;
    public final androidx.camera.camera2.internal.compat.q b;
    public final androidx.camera.core.impl.utils.executor.k c;
    public final androidx.camera.core.impl.utils.executor.e d;
    public final com.quizlet.data.repository.activitycenter.b e;
    public final com.quizlet.data.repository.explanations.myexplanations.a f;
    public final C0137n g;
    public final B h;
    public final F i;
    public CameraDevice j;
    public int k;
    public V l;
    public final LinkedHashMap m;
    public int n;
    public final C0145w o;
    public final androidx.camera.camera2.internal.concurrent.a p;
    public final androidx.camera.core.impl.D q;
    public final boolean r;
    public final boolean s;
    public boolean t;
    public boolean u;
    public boolean v;
    public c0 w;
    public final c0 x;
    public final c0 y;
    public final HashSet z;

    public C(Context context, androidx.camera.camera2.internal.compat.q qVar, String str, F f, androidx.camera.camera2.internal.concurrent.a aVar, androidx.camera.core.impl.D d, Executor executor, Handler handler, W w, long j) throws CameraUnavailableException {
        com.quizlet.data.repository.activitycenter.b bVar = new com.quizlet.data.repository.activitycenter.b(2);
        this.e = bVar;
        this.k = 0;
        new AtomicInteger(0);
        this.m = new LinkedHashMap();
        this.n = 0;
        this.t = false;
        this.u = false;
        this.v = true;
        this.z = new HashSet();
        this.A = AbstractC0180t.a;
        this.B = new Object();
        this.C = false;
        this.G = new com.quizlet.data.interactor.school.b(this);
        this.b = qVar;
        this.p = aVar;
        this.q = d;
        androidx.camera.core.impl.utils.executor.e eVar = new androidx.camera.core.impl.utils.executor.e(handler);
        this.d = eVar;
        androidx.camera.core.impl.utils.executor.k kVar = new androidx.camera.core.impl.utils.executor.k(executor);
        this.c = kVar;
        this.h = new B(this, kVar, eVar, j);
        this.a = new y0(str);
        ((androidx.lifecycle.Y) bVar.b).j(new androidx.camera.core.impl.V(EnumC0184x.CLOSED));
        com.quizlet.data.repository.explanations.myexplanations.a aVar2 = new com.quizlet.data.repository.explanations.myexplanations.a(d);
        this.f = aVar2;
        c0 c0Var = new c0(kVar);
        this.x = c0Var;
        this.D = w;
        try {
            androidx.camera.camera2.internal.compat.k kVarB = qVar.b(str);
            C0137n c0137n = new C0137n(kVarB, eVar, kVar, new com.airbnb.lottie.network.d(this, 3), f.h);
            this.g = c0137n;
            this.i = f;
            f.k(c0137n);
            f.f.n((androidx.lifecycle.Y) aVar2.c);
            this.E = com.google.firebase.platforminfo.c.m(kVarB);
            this.l = z();
            this.y = new c0(handler, c0Var, f.h, androidx.camera.camera2.internal.compat.quirk.b.a, eVar, kVar);
            this.r = f.h.a(LegacyCameraOutputConfigNullPointerQuirk.class);
            this.s = f.h.a(LegacyCameraSurfaceCleanupQuirk.class);
            C0145w c0145w = new C0145w(this, str);
            this.o = c0145w;
            com.airbnb.lottie.network.c cVar = new com.airbnb.lottie.network.c(this, 3);
            synchronized (d.b) {
                AbstractC3242q6.h("Camera is already registered: " + this, !d.e.containsKey(this));
                d.e.put(this, new androidx.camera.core.impl.C(kVar, cVar, c0145w));
            }
            qVar.a.p(kVar, c0145w);
            this.F = new f0(context, str, qVar, new com.google.android.material.shape.e(1));
        } catch (CameraAccessExceptionCompat e) {
            throw new CameraUnavailableException(e);
        }
    }

    public static String v(int i) {
        return i != 0 ? i != 1 ? i != 2 ? i != 3 ? i != 4 ? i != 5 ? "UNKNOWN ERROR" : "ERROR_CAMERA_SERVICE" : "ERROR_CAMERA_DEVICE" : "ERROR_CAMERA_DISABLED" : "ERROR_MAX_CAMERAS_IN_USE" : "ERROR_CAMERA_IN_USE" : "ERROR_NONE";
    }

    public static String w(c0 c0Var) {
        StringBuilder sb = new StringBuilder("MeteringRepeating");
        c0Var.getClass();
        sb.append(c0Var.hashCode());
        return sb.toString();
    }

    public static String x(androidx.camera.core.l0 l0Var) {
        return l0Var.f() + l0Var.hashCode();
    }

    public final void A(boolean z) {
        if (!z) {
            this.h.e.c = -1L;
        }
        this.h.a();
        this.G.j();
        t("Opening camera.");
        F(8);
        try {
            this.b.a.n(this.i.a, this.c, s());
        } catch (CameraAccessExceptionCompat e) {
            t("Unable to open camera due to " + e.getMessage());
            if (e.a == 10001) {
                E(3, new C0153e(7, e), true);
                return;
            }
            com.quizlet.data.interactor.school.b bVar = this.G;
            if (((C) bVar.c).H != 8) {
                ((C) bVar.c).t("Don't need the onError timeout handler.");
                return;
            }
            ((C) bVar.c).t("Camera waiting for onError.");
            bVar.j();
            bVar.b = new com.quizlet.data.repository.course.membership.c(bVar);
        } catch (SecurityException e2) {
            t("Unable to open camera due to " + e2.getMessage());
            F(7);
            this.h.b();
        }
    }

    public final void B() {
        int i = 0;
        AbstractC3242q6.h(null, this.H == 9);
        androidx.camera.core.impl.p0 p0VarA = this.a.a();
        if (!p0VarA.k || !p0VarA.j) {
            t("Unable to create capture session due to conflicting configurations");
            return;
        }
        if (!this.q.e(this.j.getId(), this.p.z(this.j.getId()))) {
            t("Unable to create capture session in camera operating mode = " + this.p.b);
            return;
        }
        HashMap map = new HashMap();
        Collection<androidx.camera.core.impl.q0> collectionB = this.a.b();
        Collection collectionC = this.a.c();
        C0162c c0162c = e0.a;
        ArrayList arrayList = new ArrayList(collectionC);
        Iterator it2 = collectionB.iterator();
        while (true) {
            if (!it2.hasNext()) {
                break;
            }
            androidx.camera.core.impl.q0 q0Var = (androidx.camera.core.impl.q0) it2.next();
            C0163c0 c0163c0 = q0Var.g.b;
            C0162c c0162c2 = e0.a;
            if (c0163c0.a.containsKey(c0162c2) && q0Var.b().size() != 1) {
                AbstractC3053s1.c("StreamUseCaseUtil", String.format("SessionConfig has stream use case but also contains %d surfaces, abort populateSurfaceToStreamUseCaseMapping().", Integer.valueOf(q0Var.b().size())));
                break;
            }
            if (q0Var.g.b.a.containsKey(c0162c2)) {
                int i2 = 0;
                for (androidx.camera.core.impl.q0 q0Var2 : collectionB) {
                    if (((A0) arrayList.get(i2)).x() == C0.f) {
                        AbstractC3242q6.h("MeteringRepeating should contain a surface", !q0Var2.b().isEmpty());
                        map.put((androidx.camera.core.impl.J) q0Var2.b().get(0), 1L);
                    } else if (q0Var2.g.b.a.containsKey(c0162c2) && !q0Var2.b().isEmpty()) {
                        map.put((androidx.camera.core.impl.J) q0Var2.b().get(0), (Long) q0Var2.g.b.e(c0162c2));
                    }
                    i2++;
                }
            }
        }
        V v = this.l;
        synchronized (v.a) {
            v.l = map;
        }
        V v2 = this.l;
        androidx.camera.core.impl.q0 q0VarB = p0VarA.b();
        CameraDevice cameraDevice = this.j;
        cameraDevice.getClass();
        c0 c0Var = this.y;
        com.google.common.util.concurrent.e eVarL = v2.l(q0VarB, cameraDevice, new k0((Handler) c0Var.d, (c0) c0Var.e, (androidx.camera.core.impl.i0) c0Var.f, (androidx.camera.core.impl.i0) c0Var.g, (androidx.camera.core.impl.utils.executor.e) c0Var.c, (androidx.camera.core.impl.utils.executor.k) c0Var.b));
        eVarL.a(new androidx.camera.core.impl.utils.futures.h(i, eVarL, new androidx.work.impl.model.v(this, v2)), this.c);
    }

    public final void C() {
        if (this.w != null) {
            StringBuilder sb = new StringBuilder("MeteringRepeating");
            this.w.getClass();
            sb.append(this.w.hashCode());
            String string = sb.toString();
            y0 y0Var = this.a;
            LinkedHashMap linkedHashMap = y0Var.a;
            if (linkedHashMap.containsKey(string)) {
                x0 x0Var = (x0) linkedHashMap.get(string);
                x0Var.e = false;
                if (!x0Var.f) {
                    linkedHashMap.remove(string);
                }
            }
            StringBuilder sb2 = new StringBuilder("MeteringRepeating");
            this.w.getClass();
            sb2.append(this.w.hashCode());
            String string2 = sb2.toString();
            LinkedHashMap linkedHashMap2 = y0Var.a;
            if (linkedHashMap2.containsKey(string2)) {
                x0 x0Var2 = (x0) linkedHashMap2.get(string2);
                x0Var2.f = false;
                if (!x0Var2.e) {
                    linkedHashMap2.remove(string2);
                }
            }
            c0 c0Var = this.w;
            c0Var.getClass();
            AbstractC3053s1.f(3, "MeteringRepeating");
            androidx.camera.core.g0 g0Var = (androidx.camera.core.g0) c0Var.b;
            if (g0Var != null) {
                g0Var.a();
            }
            c0Var.b = null;
            this.w = null;
        }
    }

    public final void D() {
        androidx.camera.core.impl.q0 q0Var;
        List listUnmodifiableList;
        AbstractC3242q6.h(null, this.l != null);
        t("Resetting Capture Session");
        V v = this.l;
        synchronized (v.a) {
            q0Var = v.f;
        }
        synchronized (v.a) {
            listUnmodifiableList = Collections.unmodifiableList(v.b);
        }
        V vZ = z();
        this.l = vZ;
        vZ.n(q0Var);
        this.l.j(listUnmodifiableList);
        if (AbstractC0147y.k(this.H) != 8) {
            t("Skipping Capture Session state check due to current camera state: " + AbstractC0147y.l(this.H) + " and previous session status: " + v.h());
        } else if (this.r && v.h()) {
            t("Close camera before creating new session");
            F(6);
        }
        if (this.s && v.h()) {
            t("ConfigAndClose is required when close the camera.");
            this.t = true;
        }
        v.a();
        com.google.common.util.concurrent.e eVarM = v.m();
        t("Releasing session in state ".concat(AbstractC0147y.j(this.H)));
        this.m.put(v, eVarM);
        eVarM.a(new androidx.camera.core.impl.utils.futures.h(0, eVarM, new androidx.work.impl.model.l(1, this, v)), com.google.android.gms.internal.mlkit_vision_barcode.T.a());
    }

    /* JADX WARN: Removed duplicated region for block: B:120:0x019d A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:57:0x010a  */
    /* JADX WARN: Removed duplicated region for block: B:67:0x0148 A[Catch: all -> 0x00e8, TryCatch #1 {all -> 0x00e8, blocks: (B:28:0x009f, B:30:0x00a6, B:32:0x00b0, B:46:0x00e5, B:50:0x00eb, B:52:0x00f1, B:54:0x00f5, B:56:0x0105, B:59:0x010d, B:61:0x0111, B:62:0x0120, B:64:0x0126, B:66:0x0138, B:75:0x0166, B:76:0x0169, B:67:0x0148, B:69:0x014c, B:71:0x0150, B:34:0x00b8, B:36:0x00cd, B:40:0x00d4, B:42:0x00db), top: B:122:0x009f }] */
    /* JADX WARN: Removed duplicated region for block: B:72:0x0161  */
    /* JADX WARN: Removed duplicated region for block: B:78:0x016c  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void E(int r11, androidx.camera.core.C0153e r12, boolean r13) {
        /*
            Method dump skipped, instructions count: 660
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.camera.camera2.internal.C.E(int, androidx.camera.core.e, boolean):void");
    }

    public final void F(int i) {
        E(i, null, true);
    }

    public final ArrayList G(ArrayList arrayList) {
        ArrayList arrayList2 = new ArrayList();
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            androidx.camera.core.l0 l0Var = (androidx.camera.core.l0) it2.next();
            boolean z = this.v;
            String strX = x(l0Var);
            Class<?> cls = l0Var.getClass();
            androidx.camera.core.impl.q0 q0Var = z ? l0Var.m : l0Var.n;
            A0 a0 = l0Var.f;
            C0168g c0168g = l0Var.g;
            arrayList2.add(new C0125b(strX, cls, q0Var, a0, c0168g != null ? c0168g.a : null, c0168g, l0Var.b() != null ? androidx.camera.core.streamsharing.d.F(l0Var) : null));
        }
        return arrayList2;
    }

    public final void H(ArrayList arrayList) {
        Size size;
        boolean zIsEmpty = this.a.b().isEmpty();
        ArrayList arrayList2 = new ArrayList();
        Iterator it2 = arrayList.iterator();
        Rational rational = null;
        while (true) {
            if (!it2.hasNext()) {
                break;
            }
            C0125b c0125b = (C0125b) it2.next();
            if (!this.a.d(c0125b.a)) {
                y0 y0Var = this.a;
                String str = c0125b.a;
                androidx.camera.core.impl.q0 q0Var = c0125b.c;
                A0 a0 = c0125b.d;
                C0168g c0168g = c0125b.f;
                ArrayList arrayList3 = c0125b.g;
                LinkedHashMap linkedHashMap = y0Var.a;
                x0 x0Var = (x0) linkedHashMap.get(str);
                if (x0Var == null) {
                    x0Var = new x0(q0Var, a0, c0168g, arrayList3);
                    linkedHashMap.put(str, x0Var);
                }
                x0Var.e = true;
                y0Var.i(str, q0Var, a0, c0168g, arrayList3);
                arrayList2.add(c0125b.a);
                if (c0125b.b == androidx.camera.core.X.class && (size = c0125b.e) != null) {
                    rational = new Rational(size.getWidth(), size.getHeight());
                }
            }
        }
        if (arrayList2.isEmpty()) {
            return;
        }
        t("Use cases [" + TextUtils.join(", ", arrayList2) + "] now ATTACHED");
        if (zIsEmpty) {
            this.g.m(true);
            C0137n c0137n = this.g;
            synchronized (c0137n.d) {
                c0137n.p++;
            }
        }
        p();
        L();
        K();
        D();
        if (this.H == 9) {
            B();
        } else {
            int iK = AbstractC0147y.k(this.H);
            if (iK == 2 || iK == 3) {
                I(false);
            } else if (iK != 4) {
                t("open() ignored due to being in state: ".concat(AbstractC0147y.l(this.H)));
            } else {
                F(7);
                if (!this.m.isEmpty() && !this.u && this.k == 0) {
                    AbstractC3242q6.h("Camera Device should be open if session close is not complete", this.j != null);
                    F(9);
                    B();
                }
            }
        }
        if (rational != null) {
            this.g.h.getClass();
        }
    }

    public final void I(boolean z) {
        t("Attempting to force open the camera.");
        if (this.q.d(this)) {
            A(z);
        } else {
            t("No cameras available. Waiting for available camera before opening camera.");
            F(4);
        }
    }

    public final void J(boolean z) {
        t("Attempting to open the camera.");
        if (this.o.b && this.q.d(this)) {
            A(z);
        } else {
            t("No cameras available. Waiting for available camera before opening camera.");
            F(4);
        }
    }

    public final void K() {
        y0 y0Var = this.a;
        y0Var.getClass();
        androidx.camera.core.impl.p0 p0Var = new androidx.camera.core.impl.p0();
        ArrayList arrayList = new ArrayList();
        for (Map.Entry entry : y0Var.a.entrySet()) {
            x0 x0Var = (x0) entry.getValue();
            if (x0Var.f && x0Var.e) {
                String str = (String) entry.getKey();
                p0Var.a(x0Var.a);
                arrayList.add(str);
            }
        }
        arrayList.toString();
        AbstractC3053s1.f(3, "UseCaseAttachState");
        boolean z = p0Var.k && p0Var.j;
        C0137n c0137n = this.g;
        if (!z) {
            c0137n.v = 1;
            c0137n.h.c = 1;
            c0137n.n.getClass();
            this.l.n(c0137n.j());
            return;
        }
        int i = p0Var.b().g.c;
        c0137n.v = i;
        c0137n.h.c = i;
        c0137n.n.getClass();
        p0Var.a(c0137n.j());
        this.l.n(p0Var.b());
    }

    public final void L() {
        Iterator it2 = this.a.c().iterator();
        boolean zBooleanValue = false;
        while (it2.hasNext()) {
            zBooleanValue |= ((Boolean) ((A0) it2.next()).j(A0.t0, Boolean.FALSE)).booleanValue();
        }
        this.g.l.a = zBooleanValue;
    }

    @Override // androidx.camera.core.impl.InterfaceC0185y
    public final void b(C0179s c0179s) {
        if (c0179s == null) {
            c0179s = AbstractC0180t.a;
        }
        c0179s.y();
        this.A = c0179s;
        synchronized (this.B) {
        }
    }

    @Override // androidx.camera.core.k0
    public final void c(androidx.camera.core.l0 l0Var) {
        this.c.execute(new RunnableC0140q(this, x(l0Var), this.v ? l0Var.m : l0Var.n, l0Var.f, l0Var.g, l0Var.b() == null ? null : androidx.camera.core.streamsharing.d.F(l0Var), 0));
    }

    @Override // androidx.camera.core.k0
    public final void d(androidx.camera.core.l0 l0Var) {
        l0Var.getClass();
        this.c.execute(new RunnableC0141s(this, x(l0Var), this.v ? l0Var.m : l0Var.n, l0Var.f, l0Var.g, l0Var.b() == null ? null : androidx.camera.core.streamsharing.d.F(l0Var), 0));
    }

    @Override // androidx.camera.core.k0
    public final void e(androidx.camera.core.l0 l0Var) {
        this.c.execute(new RunnableC0140q(this, x(l0Var), this.v ? l0Var.m : l0Var.n, l0Var.f, l0Var.g, l0Var.b() == null ? null : androidx.camera.core.streamsharing.d.F(l0Var), 1));
    }

    @Override // androidx.camera.core.impl.InterfaceC0185y
    public final InterfaceC0161b0 f() {
        return this.e;
    }

    @Override // androidx.camera.core.impl.InterfaceC0185y
    public final InterfaceC0182v g() {
        return this.g;
    }

    @Override // androidx.camera.core.impl.InterfaceC0185y
    public final InterfaceC0178q h() {
        return this.A;
    }

    @Override // androidx.camera.core.impl.InterfaceC0185y
    public final void i(boolean z) {
        this.c.execute(new RunnableC0142t(z, 0, this));
    }

    @Override // androidx.camera.core.impl.InterfaceC0185y
    public final void j(ArrayList arrayList) {
        ArrayList arrayList2 = new ArrayList(arrayList);
        if (arrayList2.isEmpty()) {
            return;
        }
        ArrayList arrayList3 = new ArrayList(G(arrayList2));
        Iterator it2 = new ArrayList(arrayList2).iterator();
        while (it2.hasNext()) {
            androidx.camera.core.l0 l0Var = (androidx.camera.core.l0) it2.next();
            String strX = x(l0Var);
            HashSet hashSet = this.z;
            if (hashSet.contains(strX)) {
                l0Var.t();
                hashSet.remove(strX);
            }
        }
        this.c.execute(new r(this, arrayList3, 0));
    }

    @Override // androidx.camera.core.impl.InterfaceC0185y
    public final void k(ArrayList arrayList) {
        ArrayList arrayList2 = new ArrayList(arrayList);
        if (arrayList2.isEmpty()) {
            return;
        }
        C0137n c0137n = this.g;
        synchronized (c0137n.d) {
            c0137n.p++;
        }
        Iterator it2 = new ArrayList(arrayList2).iterator();
        while (it2.hasNext()) {
            androidx.camera.core.l0 l0Var = (androidx.camera.core.l0) it2.next();
            String strX = x(l0Var);
            HashSet hashSet = this.z;
            if (!hashSet.contains(strX)) {
                hashSet.add(strX);
                l0Var.s();
                l0Var.q();
            }
        }
        try {
            this.c.execute(new r(this, new ArrayList(G(arrayList2)), 1));
        } catch (RejectedExecutionException unused) {
            t("Unable to attach use cases.");
            c0137n.i();
        }
    }

    @Override // androidx.camera.core.impl.InterfaceC0185y
    public final void m(boolean z) {
        this.v = z;
    }

    @Override // androidx.camera.core.impl.InterfaceC0185y
    public final InterfaceC0183w n() {
        return this.i;
    }

    @Override // androidx.camera.core.k0
    public final void o(androidx.camera.core.l0 l0Var) {
        this.c.execute(new androidx.activity.r(8, this, x(l0Var)));
    }

    public final void p() {
        y0 y0Var = this.a;
        androidx.camera.core.impl.q0 q0VarB = y0Var.a().b();
        androidx.camera.core.impl.F f = q0VarB.g;
        int size = Collections.unmodifiableList(f.a).size();
        int size2 = q0VarB.b().size();
        if (q0VarB.b().isEmpty()) {
            return;
        }
        if (!Collections.unmodifiableList(f.a).isEmpty()) {
            if (size2 == 1 && size == 1) {
                C();
                return;
            }
            if (size >= 2) {
                C();
                return;
            } else if (this.w == null || y()) {
                AbstractC3053s1.f(3, "Camera2CameraImpl");
                return;
            } else {
                C();
                return;
            }
        }
        if (this.w == null) {
            this.w = new c0(this.i.b, this.D, new C0139p(this, 1));
        }
        if (!y()) {
            AbstractC3053s1.c("Camera2CameraImpl", "Failed to add a repeating surface, CameraControl and ImageCapture may encounter issues due to the absence of repeating surface. Please add a UseCase (Preview or ImageAnalysis) that can provide a repeating surface for CameraControl and ImageCapture to function properly.");
            return;
        }
        c0 c0Var = this.w;
        if (c0Var != null) {
            String strW = w(c0Var);
            c0 c0Var2 = this.w;
            androidx.camera.core.impl.q0 q0Var = (androidx.camera.core.impl.q0) c0Var2.c;
            C0 c0 = C0.f;
            List listSingletonList = Collections.singletonList(c0);
            LinkedHashMap linkedHashMap = y0Var.a;
            x0 x0Var = (x0) linkedHashMap.get(strW);
            b0 b0Var = (b0) c0Var2.d;
            if (x0Var == null) {
                x0Var = new x0(q0Var, b0Var, null, listSingletonList);
                linkedHashMap.put(strW, x0Var);
            }
            x0Var.e = true;
            y0Var.i(strW, q0Var, b0Var, null, listSingletonList);
            c0 c0Var3 = this.w;
            androidx.camera.core.impl.q0 q0Var2 = (androidx.camera.core.impl.q0) c0Var3.c;
            List listSingletonList2 = Collections.singletonList(c0);
            LinkedHashMap linkedHashMap2 = y0Var.a;
            x0 x0Var2 = (x0) linkedHashMap2.get(strW);
            if (x0Var2 == null) {
                x0Var2 = new x0(q0Var2, (b0) c0Var3.d, null, listSingletonList2);
                linkedHashMap2.put(strW, x0Var2);
            }
            x0Var2.f = true;
        }
    }

    public final void q() {
        ArrayList<androidx.camera.core.impl.F> arrayList;
        AbstractC3242q6.h("closeCamera should only be called in a CLOSING, RELEASING or REOPENING (with error) state. Current state: " + AbstractC0147y.l(this.H) + " (error: " + v(this.k) + ")", this.H == 5 || this.H == 2 || (this.H == 7 && this.k != 0));
        D();
        V v = this.l;
        synchronized (v.a) {
            try {
                if (v.b.isEmpty()) {
                    arrayList = null;
                } else {
                    arrayList = new ArrayList(v.b);
                    v.b.clear();
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        if (arrayList != null) {
            for (androidx.camera.core.impl.F f : arrayList) {
                for (AbstractC0171j abstractC0171j : f.d) {
                    Object obj = f.f.a.get("CAPTURE_CONFIG_ID_KEY");
                    abstractC0171j.a(obj == null ? -1 : ((Integer) obj).intValue());
                }
            }
        }
    }

    public final void r() {
        AbstractC3242q6.h(null, this.H == 2 || this.H == 5);
        AbstractC3242q6.h(null, this.m.isEmpty());
        if (!this.t) {
            u();
            return;
        }
        if (this.u) {
            t("Ignored since configAndClose is processing");
            return;
        }
        if (!this.o.b) {
            this.t = false;
            u();
            t("Ignore configAndClose and finish the close flow directly since camera is unavailable.");
        } else {
            t("Open camera to configAndClose");
            androidx.concurrent.futures.l lVarB = Y5.b(new C0139p(this, 0));
            this.u = true;
            lVarB.b.a(new RunnableC0041m(this, 2), this.c);
        }
    }

    public final CameraDevice.StateCallback s() {
        ArrayList arrayList = new ArrayList(this.a.a().b().c);
        arrayList.add((N) this.x.g);
        arrayList.add(this.h);
        return com.facebook.appevents.iap.u.c(arrayList);
    }

    public final void t(String str) {
        toString();
        AbstractC3053s1.f(3, "Camera2CameraImpl");
    }

    public final String toString() {
        return String.format(Locale.US, "Camera@%x[id=%s]", Integer.valueOf(hashCode()), this.i.a);
    }

    public final void u() {
        AbstractC3242q6.h(null, this.H == 2 || this.H == 5);
        AbstractC3242q6.h(null, this.m.isEmpty());
        this.j = null;
        if (this.H == 5) {
            F(3);
            return;
        }
        this.b.a.u(this.o);
        F(1);
    }

    public final boolean y() {
        int i;
        ArrayList arrayList = new ArrayList();
        synchronized (this.B) {
            try {
                i = this.p.b == 2 ? 1 : 0;
            } finally {
            }
        }
        y0 y0Var = this.a;
        y0Var.getClass();
        ArrayList arrayList2 = new ArrayList();
        for (Map.Entry entry : y0Var.a.entrySet()) {
            if (((x0) entry.getValue()).e) {
                arrayList2.add((x0) entry.getValue());
            }
        }
        for (x0 x0Var : Collections.unmodifiableCollection(arrayList2)) {
            List list = x0Var.d;
            if (list == null || list.get(0) != C0.f) {
                if (x0Var.c == null || x0Var.d == null) {
                    AbstractC3053s1.h("Camera2CameraImpl", "Invalid stream spec or capture types in " + x0Var);
                    return false;
                }
                androidx.camera.core.impl.q0 q0Var = x0Var.a;
                A0 a0 = x0Var.b;
                for (androidx.camera.core.impl.J j : q0Var.b()) {
                    f0 f0Var = this.F;
                    int iO = a0.o();
                    C0169h c0169hB = C0169h.b(i, iO, j.h, f0Var.i(iO));
                    int iO2 = a0.o();
                    Size size = j.h;
                    C0168g c0168g = x0Var.c;
                    arrayList.add(new C0158a(c0169hB, iO2, size, c0168g.b, x0Var.d, c0168g.d, (Range) a0.j(A0.s0, null)));
                }
            }
        }
        this.w.getClass();
        HashMap map = new HashMap();
        c0 c0Var = this.w;
        map.put((b0) c0Var.d, Collections.singletonList((Size) c0Var.e));
        try {
            this.F.g(i, arrayList, map, false, false);
            t("Surface combination with metering repeating supported!");
            return true;
        } catch (IllegalArgumentException unused) {
            t("Surface combination with metering repeating  not supported!");
            return false;
        }
    }

    public final V z() {
        V v;
        synchronized (this.B) {
            v = new V(this.E, this.i.h, false);
        }
        return v;
    }
}

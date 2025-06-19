package androidx.camera.camera2.internal;

import android.hardware.camera2.CameraAccessException;
import android.hardware.camera2.CameraCaptureSession;
import android.hardware.camera2.CameraDevice;
import android.hardware.camera2.CaptureRequest;
import android.os.Build;
import android.os.Handler;
import android.view.Surface;
import androidx.camera.camera2.internal.compat.quirk.CaptureSessionOnClosedNotCalledQuirk;
import androidx.camera.camera2.internal.compat.quirk.CaptureSessionStuckQuirk;
import androidx.camera.camera2.internal.compat.quirk.ConfigureSurfaceToSecondarySessionFailQuirk;
import androidx.camera.camera2.internal.compat.quirk.IncorrectCaptureStateQuirk;
import androidx.camera.camera2.internal.compat.quirk.PreviewOrientationIncorrectQuirk;
import androidx.camera.camera2.internal.compat.quirk.TextureViewIsClosedQuirk;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.google.android.gms.internal.measurement.AbstractC3058t1;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;
import com.google.android.gms.internal.mlkit_vision_barcode.Y5;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicBoolean;

/* loaded from: classes.dex */
public final class k0 extends g0 {
    public final c0 b;
    public final Handler c;
    public final androidx.camera.core.impl.utils.executor.k d;
    public final androidx.camera.core.impl.utils.executor.e e;
    public U f;
    public androidx.appcompat.app.Q g;
    public androidx.concurrent.futures.l h;
    public androidx.concurrent.futures.i i;
    public androidx.camera.core.impl.utils.futures.d j;
    public final androidx.camera.core.impl.utils.executor.e o;
    public ArrayList q;
    public androidx.camera.core.impl.utils.futures.l r;
    public final androidx.camera.camera2.internal.compat.workaround.c s;
    public final com.airbnb.lottie.network.c t;
    public final androidx.appcompat.app.K u;
    public final androidx.camera.camera2.internal.compat.workaround.e v;
    public final Object a = new Object();
    public List k = null;
    public boolean l = false;
    public boolean m = false;
    public boolean n = false;
    public final Object p = new Object();
    public final AtomicBoolean w = new AtomicBoolean(false);

    public k0(Handler handler, c0 c0Var, androidx.camera.core.impl.i0 i0Var, androidx.camera.core.impl.i0 i0Var2, androidx.camera.core.impl.utils.executor.e eVar, androidx.camera.core.impl.utils.executor.k kVar) {
        this.b = c0Var;
        this.c = handler;
        this.d = kVar;
        this.e = eVar;
        androidx.camera.camera2.internal.compat.workaround.c cVar = new androidx.camera.camera2.internal.compat.workaround.c();
        cVar.a = i0Var2.a(TextureViewIsClosedQuirk.class);
        cVar.b = i0Var.a(PreviewOrientationIncorrectQuirk.class);
        cVar.c = i0Var.a(ConfigureSurfaceToSecondarySessionFailQuirk.class);
        this.s = cVar;
        this.u = new androidx.appcompat.app.K(i0Var.a(CaptureSessionStuckQuirk.class) || i0Var.a(IncorrectCaptureStateQuirk.class));
        this.t = new com.airbnb.lottie.network.c(i0Var2);
        this.v = new androidx.camera.camera2.internal.compat.workaround.e(i0Var2);
        this.o = eVar;
    }

    public static void l() {
        AbstractC3053s1.f(3, "SyncCaptureSessionImpl");
    }

    @Override // androidx.camera.camera2.internal.g0
    public final void a(k0 k0Var) {
        Objects.requireNonNull(this.f);
        this.f.a(k0Var);
    }

    @Override // androidx.camera.camera2.internal.g0
    public final void b(k0 k0Var) {
        Objects.requireNonNull(this.f);
        this.f.b(k0Var);
    }

    @Override // androidx.camera.camera2.internal.g0
    public final void c(k0 k0Var) {
        androidx.concurrent.futures.l lVar;
        synchronized (this.p) {
            this.s.b(this.q);
        }
        l();
        synchronized (this.a) {
            try {
                if (this.l) {
                    lVar = null;
                } else {
                    this.l = true;
                    AbstractC3242q6.g(this.h, "Need to call openCaptureSession before using this API.");
                    lVar = this.h;
                }
            } finally {
            }
        }
        synchronized (this.a) {
            try {
                List list = this.k;
                if (list != null) {
                    Iterator it2 = list.iterator();
                    while (it2.hasNext()) {
                        ((androidx.camera.core.impl.J) it2.next()).b();
                    }
                    this.k = null;
                }
            } finally {
            }
        }
        this.u.J();
        if (lVar != null) {
            lVar.b.a(new h0(this, k0Var, 0), com.google.android.gms.internal.mlkit_vision_barcode.T.a());
        }
    }

    @Override // androidx.camera.camera2.internal.g0
    public final void d(k0 k0Var) {
        k0 k0Var2;
        Objects.requireNonNull(this.f);
        synchronized (this.a) {
            try {
                List list = this.k;
                if (list != null) {
                    Iterator it2 = list.iterator();
                    while (it2.hasNext()) {
                        ((androidx.camera.core.impl.J) it2.next()).b();
                    }
                    this.k = null;
                }
            } finally {
            }
        }
        this.u.J();
        c0 c0Var = this.b;
        Iterator it3 = c0Var.q().iterator();
        while (it3.hasNext() && (k0Var2 = (k0) it3.next()) != this) {
            synchronized (k0Var2.a) {
                try {
                    List list2 = k0Var2.k;
                    if (list2 != null) {
                        Iterator it4 = list2.iterator();
                        while (it4.hasNext()) {
                            ((androidx.camera.core.impl.J) it4.next()).b();
                        }
                        k0Var2.k = null;
                    }
                } finally {
                }
            }
            k0Var2.u.J();
        }
        synchronized (c0Var.c) {
            ((LinkedHashSet) c0Var.f).remove(this);
        }
        this.f.d(k0Var);
    }

    @Override // androidx.camera.camera2.internal.g0
    public final void e(k0 k0Var) {
        ArrayList arrayList;
        k0 k0Var2;
        k0 k0Var3;
        k0 k0Var4;
        l();
        com.airbnb.lottie.network.c cVar = this.t;
        c0 c0Var = this.b;
        synchronized (c0Var.c) {
            arrayList = new ArrayList((LinkedHashSet) c0Var.f);
        }
        ArrayList arrayListN = this.b.n();
        if (((CaptureSessionOnClosedNotCalledQuirk) cVar.b) != null) {
            LinkedHashSet<k0> linkedHashSet = new LinkedHashSet();
            Iterator it2 = arrayList.iterator();
            while (it2.hasNext() && (k0Var4 = (k0) it2.next()) != k0Var) {
                linkedHashSet.add(k0Var4);
            }
            for (k0 k0Var5 : linkedHashSet) {
                k0Var5.getClass();
                k0Var5.d(k0Var5);
            }
        }
        Objects.requireNonNull(this.f);
        c0 c0Var2 = this.b;
        synchronized (c0Var2.c) {
            ((LinkedHashSet) c0Var2.d).add(this);
            ((LinkedHashSet) c0Var2.f).remove(this);
        }
        Iterator it3 = c0Var2.q().iterator();
        while (it3.hasNext() && (k0Var3 = (k0) it3.next()) != this) {
            synchronized (k0Var3.a) {
                try {
                    List list = k0Var3.k;
                    if (list != null) {
                        Iterator it4 = list.iterator();
                        while (it4.hasNext()) {
                            ((androidx.camera.core.impl.J) it4.next()).b();
                        }
                        k0Var3.k = null;
                    }
                } catch (Throwable th) {
                    throw th;
                }
            }
            k0Var3.u.J();
        }
        this.f.e(k0Var);
        if (((CaptureSessionOnClosedNotCalledQuirk) cVar.b) != null) {
            LinkedHashSet<k0> linkedHashSet2 = new LinkedHashSet();
            Iterator it5 = arrayListN.iterator();
            while (it5.hasNext() && (k0Var2 = (k0) it5.next()) != k0Var) {
                linkedHashSet2.add(k0Var2);
            }
            for (k0 k0Var6 : linkedHashSet2) {
                k0Var6.getClass();
                k0Var6.c(k0Var6);
            }
        }
    }

    @Override // androidx.camera.camera2.internal.g0
    public final void f(k0 k0Var) {
        Objects.requireNonNull(this.f);
        this.f.f(k0Var);
    }

    @Override // androidx.camera.camera2.internal.g0
    public final void g(k0 k0Var) {
        androidx.concurrent.futures.l lVar;
        synchronized (this.a) {
            try {
                if (this.n) {
                    lVar = null;
                } else {
                    this.n = true;
                    AbstractC3242q6.g(this.h, "Need to call openCaptureSession before using this API.");
                    lVar = this.h;
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        if (lVar != null) {
            lVar.b.a(new h0(this, k0Var, 1), com.google.android.gms.internal.mlkit_vision_barcode.T.a());
        }
    }

    @Override // androidx.camera.camera2.internal.g0
    public final void h(k0 k0Var, Surface surface) {
        Objects.requireNonNull(this.f);
        this.f.h(k0Var, surface);
    }

    public final int i(ArrayList arrayList, C0135l c0135l) {
        CameraCaptureSession.CaptureCallback captureCallbackP = this.u.p(c0135l);
        AbstractC3242q6.g(this.g, "Need to call openCaptureSession before using this API.");
        return ((com.quizlet.data.repository.searchexplanations.c) this.g.a).c(arrayList, this.d, captureCallbackP);
    }

    public final void j() throws CameraAccessException {
        if (!this.w.compareAndSet(false, true)) {
            l();
            return;
        }
        if (this.v.b) {
            try {
                l();
                AbstractC3242q6.g(this.g, "Need to call openCaptureSession before using this API.");
                ((CameraCaptureSession) ((com.quizlet.data.repository.searchexplanations.c) this.g.a).b).abortCaptures();
            } catch (Exception e) {
                e.toString();
                l();
            }
        }
        l();
        this.u.r().a(new i0(this, 1), this.d);
    }

    public final void k(CameraCaptureSession cameraCaptureSession) {
        if (this.g == null) {
            Handler handler = this.c;
            androidx.appcompat.app.Q q = new androidx.appcompat.app.Q();
            if (Build.VERSION.SDK_INT >= 28) {
                q.a = new androidx.camera.camera2.internal.compat.g(cameraCaptureSession, null);
            } else {
                q.a = new com.quizlet.data.repository.searchexplanations.c(cameraCaptureSession, new androidx.camera.camera2.internal.compat.h(handler));
            }
            this.g = q;
        }
    }

    public final boolean m() {
        boolean z;
        synchronized (this.a) {
            z = this.h != null;
        }
        return z;
    }

    public final com.google.common.util.concurrent.e n(CameraDevice cameraDevice, androidx.camera.camera2.internal.compat.params.q qVar, List list) {
        com.google.common.util.concurrent.e eVarD;
        synchronized (this.p) {
            try {
                ArrayList arrayListN = this.b.n();
                ArrayList arrayList = new ArrayList();
                Iterator it2 = arrayListN.iterator();
                while (it2.hasNext()) {
                    k0 k0Var = (k0) it2.next();
                    arrayList.add(Y5.b(new androidx.camera.core.impl.utils.futures.e(k0Var.u.r(), k0Var.o, 1500L, 0)));
                }
                androidx.camera.core.impl.utils.futures.l lVar = new androidx.camera.core.impl.utils.futures.l(new ArrayList(arrayList), false, com.google.android.gms.internal.mlkit_vision_barcode.T.a());
                this.r = lVar;
                androidx.camera.core.impl.utils.futures.d dVarC = androidx.camera.core.impl.utils.futures.d.c(lVar);
                j0 j0Var = new j0(this, cameraDevice, qVar, list);
                androidx.camera.core.impl.utils.executor.k kVar = this.d;
                dVarC.getClass();
                eVarD = androidx.camera.core.impl.utils.futures.i.d(androidx.camera.core.impl.utils.futures.i.f(dVarC, j0Var, kVar));
            } catch (Throwable th) {
                throw th;
            }
        }
        return eVarD;
    }

    public final int o(CaptureRequest captureRequest, CameraCaptureSession.CaptureCallback captureCallback) {
        CameraCaptureSession.CaptureCallback captureCallbackP = this.u.p(captureCallback);
        AbstractC3242q6.g(this.g, "Need to call openCaptureSession before using this API.");
        return ((com.quizlet.data.repository.searchexplanations.c) this.g.a).o(captureRequest, this.d, captureCallbackP);
    }

    public final com.google.common.util.concurrent.e p(ArrayList arrayList) {
        synchronized (this.a) {
            try {
                if (this.m) {
                    return new androidx.camera.core.impl.utils.futures.k(new CancellationException("Opener is disabled"), 1);
                }
                androidx.camera.core.impl.utils.futures.d dVarC = androidx.camera.core.impl.utils.futures.d.c(AbstractC3058t1.c(arrayList, this.d, this.e));
                C0143u c0143u = new C0143u(1, this, arrayList);
                androidx.camera.core.impl.utils.executor.k kVar = this.d;
                dVarC.getClass();
                androidx.camera.core.impl.utils.futures.b bVarF = androidx.camera.core.impl.utils.futures.i.f(dVarC, c0143u, kVar);
                this.j = bVarF;
                return androidx.camera.core.impl.utils.futures.i.d(bVarF);
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public final boolean q() {
        boolean z;
        synchronized (this.p) {
            try {
                if (m()) {
                    this.s.b(this.q);
                } else {
                    androidx.camera.core.impl.utils.futures.l lVar = this.r;
                    if (lVar != null) {
                        lVar.cancel(true);
                    }
                }
                try {
                    synchronized (this.a) {
                        try {
                            if (!this.m) {
                                androidx.camera.core.impl.utils.futures.d dVar = this.j;
                                dVar = dVar != null ? dVar : null;
                                this.m = true;
                            }
                            z = !m();
                        } finally {
                        }
                    }
                } finally {
                    if (dVar != null) {
                        dVar.cancel(true);
                    }
                }
            } finally {
            }
        }
        return z;
    }

    public final androidx.appcompat.app.Q r() {
        this.g.getClass();
        return this.g;
    }
}

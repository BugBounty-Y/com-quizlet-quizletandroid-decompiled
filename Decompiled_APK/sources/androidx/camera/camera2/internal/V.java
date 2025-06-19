package androidx.camera.camera2.internal;

import android.hardware.camera2.CameraAccessException;
import android.hardware.camera2.CameraCaptureSession;
import android.hardware.camera2.CameraDevice;
import android.hardware.camera2.CaptureRequest;
import android.view.Surface;
import androidx.activity.RunnableC0041m;
import androidx.camera.camera2.internal.compat.quirk.CaptureNoResponseQuirk;
import androidx.camera.core.impl.AbstractC0171j;
import androidx.camera.core.impl.C0166e;
import androidx.camera.core.impl.InterfaceC0177p;
import androidx.camera.core.impl.utils.SurfaceUtil;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;
import com.google.android.gms.internal.mlkit_vision_barcode.Y5;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;

/* loaded from: classes.dex */
public final class V {
    public k0 d;
    public k0 e;
    public androidx.camera.core.impl.q0 f;
    public int i;
    public androidx.concurrent.futures.l j;
    public androidx.concurrent.futures.i k;
    public final androidx.appcompat.app.K o;
    public final com.google.firebase.platforminfo.c p;
    public final androidx.camera.camera2.internal.compat.workaround.a q;
    public final boolean r;
    public final Object a = new Object();
    public final ArrayList b = new ArrayList();
    public final HashMap g = new HashMap();
    public List h = Collections.EMPTY_LIST;
    public HashMap l = new HashMap();
    public final androidx.camera.camera2.internal.compat.workaround.e m = new androidx.camera.camera2.internal.compat.workaround.e(1);
    public final androidx.camera.camera2.internal.compat.workaround.e n = new androidx.camera.camera2.internal.compat.workaround.e(2);
    public final U c = new U(this);

    public V(com.google.firebase.platforminfo.c cVar, androidx.camera.core.impl.i0 i0Var, boolean z) {
        this.i = 1;
        this.i = 2;
        this.p = cVar;
        this.o = new androidx.appcompat.app.K(i0Var.a(CaptureNoResponseQuirk.class));
        this.q = new androidx.camera.camera2.internal.compat.workaround.a(i0Var, 1);
        this.r = z;
    }

    public static G b(List list, CameraCaptureSession.CaptureCallback... captureCallbackArr) {
        CameraCaptureSession.CaptureCallback g;
        ArrayList arrayList = new ArrayList(list.size() + captureCallbackArr.length);
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            AbstractC0171j abstractC0171j = (AbstractC0171j) it2.next();
            if (abstractC0171j == null) {
                g = null;
            } else {
                ArrayList arrayList2 = new ArrayList();
                com.fasterxml.uuid.b.c(abstractC0171j, arrayList2);
                g = arrayList2.size() == 1 ? (CameraCaptureSession.CaptureCallback) arrayList2.get(0) : new G(arrayList2);
            }
            arrayList.add(g);
        }
        Collections.addAll(arrayList, captureCallbackArr);
        return new G(arrayList);
    }

    public static HashMap c(HashMap map, HashMap map2) {
        HashMap map3 = new HashMap();
        for (Integer num : map.keySet()) {
            num.getClass();
            ArrayList arrayList = new ArrayList();
            Iterator it2 = ((List) map.get(num)).iterator();
            if (it2.hasNext()) {
                SurfaceUtil.a((Surface) map2.get(((C0166e) it2.next()).a));
                Q.b();
                throw null;
            }
            AbstractC3053s1.c("CaptureSession", "Skips to create instances for multi-resolution output. imageFormat: 0, streamInfos size: " + arrayList.size());
        }
        return map3;
    }

    public static ArrayList f(ArrayList arrayList) {
        ArrayList arrayList2 = new ArrayList();
        ArrayList arrayList3 = new ArrayList();
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            androidx.camera.camera2.internal.compat.params.h hVar = (androidx.camera.camera2.internal.compat.params.h) it2.next();
            if (!arrayList2.contains(hVar.a.c())) {
                arrayList2.add(hVar.a.c());
                arrayList3.add(hVar);
            }
        }
        return arrayList3;
    }

    public static HashMap g(ArrayList arrayList) {
        HashMap map = new HashMap();
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            C0166e c0166e = (C0166e) it2.next();
            if (c0166e.d > 0 && c0166e.b.isEmpty()) {
                int i = c0166e.d;
                List arrayList2 = (List) map.get(Integer.valueOf(i));
                if (arrayList2 == null) {
                    arrayList2 = new ArrayList();
                    map.put(Integer.valueOf(i), arrayList2);
                }
                arrayList2.add(c0166e);
            }
        }
        HashMap map2 = new HashMap();
        for (Integer num : map.keySet()) {
            num.getClass();
            if (((List) map.get(num)).size() >= 2) {
                map2.put(num, (List) map.get(num));
            }
        }
        return map2;
    }

    public final void a() {
        synchronized (this.a) {
            try {
                int iK = AbstractC0147y.k(this.i);
                if (iK == 0) {
                    throw new IllegalStateException("close() should not be possible in state: ".concat(AbstractC0147y.m(this.i)));
                }
                if (iK == 1) {
                    this.i = 8;
                } else if (iK == 2) {
                    AbstractC3242q6.g(this.d, "The Opener shouldn't null in state:".concat(AbstractC0147y.m(this.i)));
                    this.d.q();
                    this.i = 8;
                } else if (iK == 3 || iK == 4) {
                    AbstractC3242q6.g(this.d, "The Opener shouldn't null in state:".concat(AbstractC0147y.m(this.i)));
                    this.d.q();
                    this.i = 6;
                    this.o.J();
                    this.f = null;
                }
            } finally {
            }
        }
    }

    public final void d() {
        if (this.i == 8) {
            AbstractC3053s1.f(3, "CaptureSession");
            return;
        }
        this.i = 8;
        this.e = null;
        androidx.concurrent.futures.i iVar = this.k;
        if (iVar != null) {
            iVar.b(null);
            this.k = null;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:29:0x00a2  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final androidx.camera.camera2.internal.compat.params.h e(androidx.camera.core.impl.C0166e r7, java.util.HashMap r8, java.lang.String r9) {
        /*
            r6 = this;
            androidx.camera.core.impl.J r0 = r7.a
            java.lang.Object r0 = r8.get(r0)
            android.view.Surface r0 = (android.view.Surface) r0
            java.lang.String r1 = "Surface in OutputConfig not found in configuredSurfaceMap."
            com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6.g(r0, r1)
            androidx.camera.camera2.internal.compat.params.h r2 = new androidx.camera.camera2.internal.compat.params.h
            int r3 = r7.d
            r2.<init>(r3, r0)
            androidx.camera.camera2.internal.compat.params.j r0 = r2.a
            if (r9 == 0) goto L1c
            r0.f(r9)
            goto L20
        L1c:
            r9 = 0
            r0.f(r9)
        L20:
            r9 = 1
            int r3 = r7.c
            if (r3 != 0) goto L29
            r0.e(r9)
            goto L2f
        L29:
            if (r3 != r9) goto L2f
            r3 = 2
            r0.e(r3)
        L2f:
            java.util.List r3 = r7.b
            boolean r4 = r3.isEmpty()
            if (r4 != 0) goto L63
            java.lang.Object r4 = r0.a()
            android.hardware.camera2.params.OutputConfiguration r4 = (android.hardware.camera2.params.OutputConfiguration) r4
            r4.enableSurfaceSharing()
            java.util.Iterator r3 = r3.iterator()
        L44:
            boolean r4 = r3.hasNext()
            if (r4 == 0) goto L63
            java.lang.Object r4 = r3.next()
            androidx.camera.core.impl.J r4 = (androidx.camera.core.impl.J) r4
            java.lang.Object r4 = r8.get(r4)
            android.view.Surface r4 = (android.view.Surface) r4
            com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6.g(r4, r1)
            java.lang.Object r5 = r0.a()
            android.hardware.camera2.params.OutputConfiguration r5 = (android.hardware.camera2.params.OutputConfiguration) r5
            r5.addSurface(r4)
            goto L44
        L63:
            int r8 = android.os.Build.VERSION.SDK_INT
            r1 = 33
            if (r8 < r1) goto La2
            com.google.firebase.platforminfo.c r3 = r6.p
            r3.getClass()
            if (r8 < r1) goto L71
            goto L72
        L71:
            r9 = 0
        L72:
            java.lang.String r8 = "DynamicRangesCompat can only be converted to DynamicRangeProfiles on API 33 or higher."
            com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6.h(r8, r9)
            java.lang.Object r8 = r3.a
            androidx.camera.camera2.internal.compat.params.b r8 = (androidx.camera.camera2.internal.compat.params.b) r8
            android.hardware.camera2.params.DynamicRangeProfiles r8 = r8.a()
            if (r8 == 0) goto La2
            androidx.camera.core.t r7 = r7.e
            java.lang.Long r8 = androidx.camera.camera2.internal.compat.params.a.a(r7, r8)
            if (r8 != 0) goto L9d
            java.lang.StringBuilder r8 = new java.lang.StringBuilder
            java.lang.String r9 = "Requested dynamic range is not supported. Defaulting to STANDARD dynamic range profile.\nRequested dynamic range:\n  "
            r8.<init>(r9)
            r8.append(r7)
            java.lang.String r7 = r8.toString()
            java.lang.String r8 = "CaptureSession"
            com.google.android.gms.internal.measurement.AbstractC3053s1.c(r8, r7)
            goto La2
        L9d:
            long r7 = r8.longValue()
            goto La4
        La2:
            r7 = 1
        La4:
            r0.d(r7)
            return r2
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.camera.camera2.internal.V.e(androidx.camera.core.impl.e, java.util.HashMap, java.lang.String):androidx.camera.camera2.internal.compat.params.h");
    }

    public final boolean h() {
        boolean z;
        synchronized (this.a) {
            int i = this.i;
            z = i == 5 || i == 4;
        }
        return z;
    }

    public final void i(ArrayList arrayList) {
        C0135l c0135l;
        ArrayList arrayList2;
        boolean z;
        InterfaceC0177p interfaceC0177p;
        synchronized (this.a) {
            try {
                if (this.i != 5) {
                    AbstractC3053s1.f(3, "CaptureSession");
                    return;
                }
                if (arrayList.isEmpty()) {
                    return;
                }
                try {
                    c0135l = new C0135l(1);
                    arrayList2 = new ArrayList();
                    AbstractC3053s1.f(3, "CaptureSession");
                    Iterator it2 = arrayList.iterator();
                    z = false;
                    while (it2.hasNext()) {
                        androidx.camera.core.impl.F f = (androidx.camera.core.impl.F) it2.next();
                        if (Collections.unmodifiableList(f.a).isEmpty()) {
                            AbstractC3053s1.f(3, "CaptureSession");
                        } else {
                            Iterator it3 = Collections.unmodifiableList(f.a).iterator();
                            while (true) {
                                if (it3.hasNext()) {
                                    androidx.camera.core.impl.J j = (androidx.camera.core.impl.J) it3.next();
                                    if (!this.g.containsKey(j)) {
                                        Objects.toString(j);
                                        AbstractC3053s1.f(3, "CaptureSession");
                                        break;
                                    }
                                } else {
                                    if (f.c == 2) {
                                        z = true;
                                    }
                                    androidx.camera.core.a0 a0Var = new androidx.camera.core.a0(f);
                                    if (f.c == 5 && (interfaceC0177p = f.g) != null) {
                                        a0Var.g = interfaceC0177p;
                                    }
                                    androidx.camera.core.impl.q0 q0Var = this.f;
                                    if (q0Var != null) {
                                        a0Var.d(q0Var.g.b);
                                    }
                                    a0Var.d(f.b);
                                    androidx.camera.core.impl.F fE = a0Var.e();
                                    k0 k0Var = this.e;
                                    k0Var.g.getClass();
                                    CaptureRequest captureRequestE = com.facebook.appevents.codeless.i.e(fE, ((CameraCaptureSession) ((com.quizlet.data.repository.searchexplanations.c) k0Var.g.a).b).getDevice(), this.g, false, this.q);
                                    if (captureRequestE == null) {
                                        AbstractC3053s1.f(3, "CaptureSession");
                                        return;
                                    }
                                    ArrayList arrayList3 = new ArrayList();
                                    Iterator it4 = f.d.iterator();
                                    while (it4.hasNext()) {
                                        com.fasterxml.uuid.b.c((AbstractC0171j) it4.next(), arrayList3);
                                    }
                                    c0135l.a(captureRequestE, arrayList3);
                                    arrayList2.add(captureRequestE);
                                }
                            }
                        }
                    }
                } catch (CameraAccessException e) {
                    AbstractC3053s1.c("CaptureSession", "Unable to access camera: " + e.getMessage());
                    Thread.dumpStack();
                }
                if (arrayList2.isEmpty()) {
                    AbstractC3053s1.f(3, "CaptureSession");
                    return;
                }
                if (this.m.q(arrayList2, z)) {
                    k0 k0Var2 = this.e;
                    AbstractC3242q6.g(k0Var2.g, "Need to call openCaptureSession before using this API.");
                    ((CameraCaptureSession) ((com.quizlet.data.repository.searchexplanations.c) k0Var2.g.a).b).stopRepeating();
                    c0135l.c = new S(this);
                }
                if (this.n.o(arrayList2, z)) {
                    c0135l.a((CaptureRequest) arrayList2.get(arrayList2.size() - 1), Collections.singletonList(new G(this)));
                }
                this.e.i(arrayList2, c0135l);
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public final void j(List list) {
        synchronized (this.a) {
            try {
                switch (AbstractC0147y.k(this.i)) {
                    case 0:
                        throw new IllegalStateException("issueCaptureRequests() should not be possible in state: ".concat(AbstractC0147y.m(this.i)));
                    case 1:
                    case 2:
                    case 3:
                        this.b.addAll(list);
                        break;
                    case 4:
                        this.b.addAll(list);
                        this.o.r().a(new RunnableC0041m(this, 5), com.google.android.gms.internal.mlkit_vision_barcode.T.a());
                        break;
                    case 5:
                    case 6:
                    case 7:
                        throw new IllegalStateException("Cannot issue capture request on a closed/released session.");
                }
            } finally {
            }
        }
    }

    public final void k(androidx.camera.core.impl.q0 q0Var) {
        synchronized (this.a) {
            try {
            } catch (Throwable th) {
                throw th;
            }
            if (q0Var == null) {
                AbstractC3053s1.f(3, "CaptureSession");
                return;
            }
            if (this.i != 5) {
                AbstractC3053s1.f(3, "CaptureSession");
                return;
            }
            androidx.camera.core.impl.F f = q0Var.g;
            if (Collections.unmodifiableList(f.a).isEmpty()) {
                AbstractC3053s1.f(3, "CaptureSession");
                try {
                    k0 k0Var = this.e;
                    AbstractC3242q6.g(k0Var.g, "Need to call openCaptureSession before using this API.");
                    ((CameraCaptureSession) ((com.quizlet.data.repository.searchexplanations.c) k0Var.g.a).b).stopRepeating();
                } catch (CameraAccessException e) {
                    AbstractC3053s1.c("CaptureSession", "Unable to access camera: " + e.getMessage());
                    Thread.dumpStack();
                }
                return;
            }
            try {
                AbstractC3053s1.f(3, "CaptureSession");
                k0 k0Var2 = this.e;
                k0Var2.g.getClass();
                CaptureRequest captureRequestE = com.facebook.appevents.codeless.i.e(f, ((CameraCaptureSession) ((com.quizlet.data.repository.searchexplanations.c) k0Var2.g.a).b).getDevice(), this.g, true, this.q);
                if (captureRequestE == null) {
                    AbstractC3053s1.f(3, "CaptureSession");
                    return;
                } else {
                    this.e.o(captureRequestE, this.o.p(b(f.d, new CameraCaptureSession.CaptureCallback[0])));
                    return;
                }
            } catch (CameraAccessException e2) {
                AbstractC3053s1.c("CaptureSession", "Unable to access camera: " + e2.getMessage());
                Thread.dumpStack();
                return;
            }
            throw th;
        }
    }

    public final com.google.common.util.concurrent.e l(androidx.camera.core.impl.q0 q0Var, CameraDevice cameraDevice, k0 k0Var) {
        com.google.common.util.concurrent.e eVarP;
        synchronized (this.a) {
            try {
                if (AbstractC0147y.k(this.i) != 1) {
                    AbstractC3053s1.c("CaptureSession", "Open not allowed in state: ".concat(AbstractC0147y.m(this.i)));
                    return new androidx.camera.core.impl.utils.futures.k(new IllegalStateException("open() should not allow the state: ".concat(AbstractC0147y.m(this.i))), 1);
                }
                this.i = 3;
                ArrayList arrayList = new ArrayList(q0Var.b());
                this.h = arrayList;
                this.d = k0Var;
                synchronized (k0Var.p) {
                    k0Var.q = arrayList;
                    eVarP = k0Var.p(arrayList);
                }
                androidx.camera.core.impl.utils.futures.d dVarC = androidx.camera.core.impl.utils.futures.d.c(eVarP);
                T t = new T(this, q0Var, cameraDevice, 0);
                androidx.camera.core.impl.utils.executor.k kVar = this.d.d;
                dVarC.getClass();
                androidx.camera.core.impl.utils.futures.b bVarF = androidx.camera.core.impl.utils.futures.i.f(dVarC, t, kVar);
                com.google.android.gms.auth.api.signin.internal.h hVar = new com.google.android.gms.auth.api.signin.internal.h(this, 3);
                bVarF.a(new androidx.camera.core.impl.utils.futures.h(0, bVarF, hVar), this.d.d);
                return androidx.camera.core.impl.utils.futures.i.d(bVarF);
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public final com.google.common.util.concurrent.e m() {
        synchronized (this.a) {
            try {
                switch (AbstractC0147y.k(this.i)) {
                    case 0:
                        throw new IllegalStateException("release() should not be possible in state: ".concat(AbstractC0147y.m(this.i)));
                    case 2:
                        AbstractC3242q6.g(this.d, "The Opener shouldn't null in state:".concat(AbstractC0147y.m(this.i)));
                        this.d.q();
                    case 1:
                        this.i = 8;
                        return androidx.camera.core.impl.utils.futures.k.c;
                    case 4:
                    case 5:
                        k0 k0Var = this.e;
                        if (k0Var != null) {
                            k0Var.j();
                        }
                    case 3:
                        this.i = 7;
                        this.o.J();
                        AbstractC3242q6.g(this.d, "The Opener shouldn't null in state:".concat(AbstractC0147y.m(this.i)));
                        if (this.d.q()) {
                            d();
                            return androidx.camera.core.impl.utils.futures.k.c;
                        }
                    case 6:
                        if (this.j == null) {
                            this.j = Y5.b(new S(this));
                        }
                        return this.j;
                    default:
                        return androidx.camera.core.impl.utils.futures.k.c;
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public final void n(androidx.camera.core.impl.q0 q0Var) {
        synchronized (this.a) {
            try {
                switch (AbstractC0147y.k(this.i)) {
                    case 0:
                        throw new IllegalStateException("setSessionConfig() should not be possible in state: ".concat(AbstractC0147y.m(this.i)));
                    case 1:
                    case 2:
                    case 3:
                        this.f = q0Var;
                        break;
                    case 4:
                        this.f = q0Var;
                        if (q0Var != null) {
                            if (!this.g.keySet().containsAll(q0Var.b())) {
                                AbstractC3053s1.c("CaptureSession", "Does not have the proper configured lists");
                                return;
                            } else {
                                AbstractC3053s1.f(3, "CaptureSession");
                                k(this.f);
                                break;
                            }
                        } else {
                            return;
                        }
                    case 5:
                    case 6:
                    case 7:
                        throw new IllegalStateException("Session configuration cannot be set on a closed/released session.");
                }
            } finally {
            }
        }
    }
}

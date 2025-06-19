package androidx.camera.camera2.internal;

import android.graphics.Rect;
import android.hardware.camera2.CameraCharacteristics;
import android.hardware.camera2.CaptureRequest;
import android.hardware.camera2.params.InputConfiguration;
import android.hardware.camera2.params.MeteringRectangle;
import android.hardware.camera2.params.StreamConfigurationMap;
import android.media.ImageWriter;
import android.os.Build;
import android.os.Looper;
import android.util.ArrayMap;
import android.util.Size;
import androidx.camera.core.C0196t;
import androidx.camera.core.CameraControl$OperationCanceledException;
import androidx.camera.core.impl.A0;
import androidx.camera.core.impl.C0162c;
import androidx.camera.core.impl.C0163c0;
import androidx.camera.core.impl.InterfaceC0177p;
import androidx.camera.core.impl.InterfaceC0182v;
import androidx.camera.core.impl.v0;
import androidx.camera.core.impl.x0;
import androidx.camera.core.impl.y0;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.google.android.gms.internal.mlkit_vision_barcode.Y5;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/* renamed from: androidx.camera.camera2.internal.n, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0137n implements InterfaceC0182v {
    public final C0135l b;
    public final androidx.camera.core.impl.utils.executor.k c;
    public final Object d = new Object();
    public final androidx.camera.camera2.internal.compat.k e;
    public final com.airbnb.lottie.network.d f;
    public final androidx.camera.core.impl.m0 g;
    public final X h;
    public final p0 i;
    public final m0 j;
    public final androidx.appcompat.app.K k;
    public final t0 l;
    public final androidx.camera.camera2.interop.c m;
    public final com.google.firebase.heartbeatinfo.e n;
    public final com.quizlet.data.repository.school.membership.a o;
    public int p;
    public volatile boolean q;
    public volatile int r;
    public final androidx.appcompat.app.L s;
    public final androidx.camera.camera2.internal.compat.workaround.a t;
    public final AtomicLong u;
    public int v;
    public long w;
    public final C0134k x;

    /* JADX WARN: Removed duplicated region for block: B:20:0x00e8  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public C0137n(androidx.camera.camera2.internal.compat.k r8, androidx.camera.core.impl.utils.executor.e r9, androidx.camera.core.impl.utils.executor.k r10, com.airbnb.lottie.network.d r11, androidx.camera.core.impl.i0 r12) {
        /*
            Method dump skipped, instructions count: 344
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.camera.camera2.internal.C0137n.<init>(androidx.camera.camera2.internal.compat.k, androidx.camera.core.impl.utils.executor.e, androidx.camera.core.impl.utils.executor.k, com.airbnb.lottie.network.d, androidx.camera.core.impl.i0):void");
    }

    public static int k(androidx.camera.camera2.internal.compat.k kVar, int i) {
        int[] iArr = (int[]) kVar.a(CameraCharacteristics.CONTROL_AE_AVAILABLE_MODES);
        if (iArr == null) {
            return 0;
        }
        return l(iArr, i) ? i : l(iArr, 1) ? 1 : 0;
    }

    public static boolean l(int[] iArr, int i) {
        for (int i2 : iArr) {
            if (i == i2) {
                return true;
            }
        }
        return false;
    }

    @Override // androidx.camera.core.impl.InterfaceC0182v
    public final void a(androidx.camera.core.impl.H h) {
        androidx.camera.camera2.interop.c cVar = this.m;
        androidx.appcompat.app.L lH = com.google.firebase.platforminfo.c.l(h).h();
        synchronized (cVar.a) {
            androidx.camera.camera2.impl.a aVar = (androidx.camera.camera2.impl.a) cVar.f;
            aVar.getClass();
            androidx.camera.core.impl.G g = androidx.camera.core.impl.G.c;
            for (C0162c c0162c : lH.f()) {
                aVar.b.l(c0162c, g, lH.e(c0162c));
            }
        }
        androidx.camera.core.impl.utils.futures.i.d(Y5.b(new androidx.camera.camera2.interop.a(cVar, 0))).a(new RunnableC0131h(0), com.google.android.gms.internal.mlkit_vision_barcode.T.a());
    }

    @Override // androidx.camera.core.impl.InterfaceC0182v
    public final Rect b() {
        Rect rect = (Rect) this.e.a(CameraCharacteristics.SENSOR_INFO_ACTIVE_ARRAY_SIZE);
        if ("robolectric".equals(Build.FINGERPRINT) && rect == null) {
            return new Rect(0, 0, 4000, 3000);
        }
        rect.getClass();
        return rect;
    }

    @Override // androidx.camera.core.impl.InterfaceC0182v
    public final void c(int i) {
        int i2;
        synchronized (this.d) {
            i2 = this.p;
        }
        if (!(i2 > 0)) {
            AbstractC3053s1.h("Camera2CameraControlImp", "Camera is not active.");
            return;
        }
        this.r = i;
        AbstractC3053s1.f(3, "Camera2CameraControlImp");
        t0 t0Var = this.l;
        if (this.r != 1) {
            int i3 = this.r;
        }
        t0Var.getClass();
        androidx.camera.core.impl.utils.futures.i.d(Y5.b(new C0132i(this, 0)));
    }

    @Override // androidx.camera.core.impl.InterfaceC0182v
    public final void d(androidx.camera.core.impl.m0 m0Var) throws Exception {
        boolean zIsEmpty;
        HashMap map;
        StreamConfigurationMap streamConfigurationMap;
        int[] validOutputFormatsForInput;
        t0 t0Var = this.l;
        com.quizlet.data.repository.user.a aVar = (com.quizlet.data.repository.user.a) t0Var.e;
        while (true) {
            synchronized (aVar.c) {
                zIsEmpty = ((ArrayDeque) aVar.b).isEmpty();
            }
            if (zIsEmpty) {
                break;
            } else {
                ((androidx.camera.core.O) aVar.l()).close();
            }
        }
        androidx.camera.core.g0 g0Var = (androidx.camera.core.g0) t0Var.h;
        StreamConfigurationMap streamConfigurationMap2 = null;
        if (g0Var != null) {
            androidx.camera.core.a0 a0Var = (androidx.camera.core.a0) t0Var.f;
            if (a0Var != null) {
                androidx.camera.core.impl.utils.futures.i.d(g0Var.e).a(new r0(a0Var, 0), com.google.android.gms.internal.mlkit_vision_barcode.T.e());
                t0Var.f = null;
            }
            g0Var.a();
            t0Var.h = null;
        }
        ImageWriter imageWriter = (ImageWriter) t0Var.i;
        if (imageWriter != null) {
            imageWriter.close();
            t0Var.i = null;
        }
        if (t0Var.a) {
            m0Var.b.a = 1;
            return;
        }
        if (t0Var.c) {
            m0Var.b.a = 1;
            return;
        }
        try {
            streamConfigurationMap2 = (StreamConfigurationMap) ((androidx.camera.camera2.internal.compat.k) t0Var.d).a(CameraCharacteristics.SCALER_STREAM_CONFIGURATION_MAP);
        } catch (AssertionError e) {
            AbstractC3053s1.c("ZslControlImpl", "Failed to retrieve StreamConfigurationMap, error = " + e.getMessage());
        }
        if (streamConfigurationMap2 == null || streamConfigurationMap2.getInputFormats() == null) {
            map = new HashMap();
        } else {
            map = new HashMap();
            for (int i : streamConfigurationMap2.getInputFormats()) {
                Size[] inputSizes = streamConfigurationMap2.getInputSizes(i);
                if (inputSizes != null) {
                    Arrays.sort(inputSizes, new androidx.camera.core.impl.utils.c(true));
                    map.put(Integer.valueOf(i), inputSizes[0]);
                }
            }
        }
        if (t0Var.b && !map.isEmpty() && map.containsKey(34) && (streamConfigurationMap = (StreamConfigurationMap) ((androidx.camera.camera2.internal.compat.k) t0Var.d).a(CameraCharacteristics.SCALER_STREAM_CONFIGURATION_MAP)) != null && (validOutputFormatsForInput = streamConfigurationMap.getValidOutputFormatsForInput(34)) != null) {
            for (int i2 : validOutputFormatsForInput) {
                if (i2 == 256) {
                    Size size = (Size) map.get(34);
                    androidx.camera.core.T t = new androidx.camera.core.T(size.getWidth(), size.getHeight(), 34, 9);
                    t0Var.g = t.b;
                    t0Var.f = new androidx.camera.core.a0(t);
                    t.G(new C0132i(t0Var, 2), com.google.android.gms.internal.mlkit_vision_barcode.T.d());
                    androidx.camera.core.g0 g0Var2 = new androidx.camera.core.g0(((androidx.camera.core.a0) t0Var.f).w(), new Size(((androidx.camera.core.a0) t0Var.f).getWidth(), ((androidx.camera.core.a0) t0Var.f).b()), 34);
                    t0Var.h = g0Var2;
                    androidx.camera.core.a0 a0Var2 = (androidx.camera.core.a0) t0Var.f;
                    com.google.common.util.concurrent.e eVarD = androidx.camera.core.impl.utils.futures.i.d(g0Var2.e);
                    Objects.requireNonNull(a0Var2);
                    eVarD.a(new r0(a0Var2, 0), com.google.android.gms.internal.mlkit_vision_barcode.T.e());
                    m0Var.b((androidx.camera.core.g0) t0Var.h, C0196t.d, -1);
                    androidx.camera.core.S s = (androidx.camera.core.S) t0Var.g;
                    m0Var.b.c(s);
                    ArrayList arrayList = m0Var.e;
                    if (!arrayList.contains(s)) {
                        arrayList.add(s);
                    }
                    L l = new L(t0Var, 2);
                    ArrayList arrayList2 = m0Var.d;
                    if (!arrayList2.contains(l)) {
                        arrayList2.add(l);
                    }
                    m0Var.g = new InputConfiguration(((androidx.camera.core.a0) t0Var.f).getWidth(), ((androidx.camera.core.a0) t0Var.f).b(), ((androidx.camera.core.a0) t0Var.f).m());
                    return;
                }
            }
        }
        m0Var.b.a = 1;
    }

    @Override // androidx.camera.core.impl.InterfaceC0182v
    public final androidx.camera.core.impl.H e() {
        androidx.camera.camera2.impl.b bVar;
        androidx.camera.camera2.interop.c cVar = this.m;
        synchronized (cVar.a) {
            androidx.camera.camera2.impl.a aVar = (androidx.camera.camera2.impl.a) cVar.f;
            aVar.getClass();
            bVar = new androidx.camera.camera2.impl.b(C0163c0.a(aVar.b), 4);
        }
        return bVar;
    }

    @Override // androidx.camera.core.impl.InterfaceC0182v
    public final void f(androidx.camera.core.J j) {
    }

    @Override // androidx.camera.core.impl.InterfaceC0182v
    public final void g() {
        androidx.camera.camera2.interop.c cVar = this.m;
        synchronized (cVar.a) {
            cVar.f = new androidx.camera.camera2.impl.a(0);
        }
        androidx.camera.core.impl.utils.futures.i.d(Y5.b(new androidx.camera.camera2.interop.a(cVar, 1))).a(new RunnableC0131h(0), com.google.android.gms.internal.mlkit_vision_barcode.T.a());
    }

    public final void h(InterfaceC0136m interfaceC0136m) {
        ((HashSet) this.b.b).add(interfaceC0136m);
    }

    public final void i() {
        synchronized (this.d) {
            try {
                int i = this.p;
                if (i == 0) {
                    throw new IllegalStateException("Decrementing use count occurs more times than incrementing");
                }
                this.p = i - 1;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:41:0x00ab  */
    /* JADX WARN: Removed duplicated region for block: B:50:0x00d7  */
    /* JADX WARN: Removed duplicated region for block: B:76:0x00fb A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:8:0x0036  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final androidx.camera.core.impl.q0 j() {
        /*
            Method dump skipped, instructions count: 360
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.camera.camera2.internal.C0137n.j():androidx.camera.core.impl.q0");
    }

    public final void m(boolean z) {
        androidx.camera.core.internal.b bVar;
        AbstractC3053s1.f(3, "Camera2CameraControlImp");
        X x = this.h;
        if (z != x.b) {
            x.b = z;
            if (!x.b) {
                C0137n c0137n = x.a;
                ((HashSet) c0137n.b.b).remove(null);
                ((HashSet) c0137n.b.b).remove(null);
                if (x.d.length > 0 && x.b) {
                    androidx.camera.core.a0 a0Var = new androidx.camera.core.a0();
                    a0Var.b = true;
                    a0Var.a = x.c;
                    androidx.camera.core.impl.X xB = androidx.camera.core.impl.X.b();
                    xB.m(androidx.camera.camera2.impl.b.U(CaptureRequest.CONTROL_AF_TRIGGER), 2);
                    a0Var.d(new androidx.camera.camera2.impl.b(C0163c0.a(xB), 4));
                    x.a.n(Collections.singletonList(a0Var.e()));
                }
                MeteringRectangle[] meteringRectangleArr = X.h;
                x.d = meteringRectangleArr;
                x.e = meteringRectangleArr;
                x.f = meteringRectangleArr;
                c0137n.o();
            }
        }
        p0 p0Var = this.i;
        if (p0Var.b != z) {
            p0Var.b = z;
            if (!z) {
                synchronized (((q0) p0Var.d)) {
                    ((q0) p0Var.d).g();
                    q0 q0Var = (q0) p0Var.d;
                    bVar = new androidx.camera.core.internal.b(q0Var.d(), q0Var.b(), q0Var.c(), q0Var.a());
                }
                Looper looperMyLooper = Looper.myLooper();
                Looper mainLooper = Looper.getMainLooper();
                androidx.lifecycle.Y y = (androidx.lifecycle.Y) p0Var.a;
                if (looperMyLooper == mainLooper) {
                    y.l(bVar);
                } else {
                    y.j(bVar);
                }
                ((o0) p0Var.e).y();
                ((C0137n) p0Var.c).o();
            }
        }
        m0 m0Var = this.j;
        if (m0Var.a != z) {
            m0Var.a = z;
            if (!z) {
                if (m0Var.b) {
                    m0Var.b = false;
                    C0137n c0137n2 = (C0137n) m0Var.c;
                    c0137n2.q = false;
                    androidx.camera.core.a0 a0Var2 = new androidx.camera.core.a0();
                    a0Var2.a = c0137n2.v;
                    a0Var2.b = true;
                    androidx.camera.core.impl.X xB2 = androidx.camera.core.impl.X.b();
                    CaptureRequest.Key key = CaptureRequest.CONTROL_AE_MODE;
                    xB2.m(androidx.camera.camera2.impl.b.U(key), Integer.valueOf(k(c0137n2.e, 1)));
                    xB2.m(androidx.camera.camera2.impl.b.U(CaptureRequest.FLASH_MODE), 0);
                    a0Var2.d(new androidx.camera.camera2.impl.b(C0163c0.a(xB2), 4));
                    c0137n2.n(Collections.singletonList(a0Var2.e()));
                    c0137n2.o();
                    androidx.lifecycle.Y y2 = (androidx.lifecycle.Y) m0Var.d;
                    if (com.google.android.gms.internal.mlkit_vision_barcode.S.e()) {
                        y2.l(0);
                    } else {
                        y2.j(0);
                    }
                }
                androidx.concurrent.futures.i iVar = (androidx.concurrent.futures.i) m0Var.e;
                if (iVar != null) {
                    iVar.d(new CameraControl$OperationCanceledException("Camera is not active."));
                    m0Var.e = null;
                }
            }
        }
        androidx.appcompat.app.K k = this.k;
        if (z != k.a) {
            k.a = z;
            if (!z) {
                synchronized (((com.google.firebase.platforminfo.c) k.b).a) {
                }
            }
        }
        androidx.camera.camera2.interop.c cVar = this.m;
        cVar.getClass();
        ((androidx.camera.core.impl.utils.executor.k) cVar.e).execute(new RunnableC0142t(z, 1, cVar));
        if (z) {
            return;
        }
        ((AtomicInteger) this.o.b).set(0);
        AbstractC3053s1.f(3, "VideoUsageControl");
    }

    public final void n(List list) {
        int iB;
        int iA;
        InterfaceC0177p interfaceC0177p;
        com.airbnb.lottie.network.d dVar = this.f;
        dVar.getClass();
        list.getClass();
        C c = (C) dVar.b;
        c.getClass();
        ArrayList arrayList = new ArrayList();
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            androidx.camera.core.impl.F f = (androidx.camera.core.impl.F) it2.next();
            HashSet hashSet = new HashSet();
            androidx.camera.core.impl.X.b();
            ArrayList arrayList2 = new ArrayList();
            androidx.camera.core.impl.Z.a();
            hashSet.addAll(f.a);
            androidx.camera.core.impl.X xK = androidx.camera.core.impl.X.k(f.b);
            arrayList2.addAll(f.d);
            ArrayMap arrayMap = new ArrayMap();
            v0 v0Var = f.f;
            for (String str : v0Var.a.keySet()) {
                arrayMap.put(str, v0Var.a.get(str));
            }
            androidx.camera.core.impl.Z z = new androidx.camera.core.impl.Z(arrayMap);
            InterfaceC0177p interfaceC0177p2 = (f.c != 5 || (interfaceC0177p = f.g) == null) ? null : interfaceC0177p;
            if (Collections.unmodifiableList(f.a).isEmpty() && f.e) {
                if (hashSet.isEmpty()) {
                    y0 y0Var = c.a;
                    y0Var.getClass();
                    ArrayList arrayList3 = new ArrayList();
                    for (Map.Entry entry : y0Var.a.entrySet()) {
                        x0 x0Var = (x0) entry.getValue();
                        if (x0Var.f && x0Var.e) {
                            arrayList3.add(((x0) entry.getValue()).a);
                        }
                    }
                    Iterator it3 = Collections.unmodifiableCollection(arrayList3).iterator();
                    while (it3.hasNext()) {
                        androidx.camera.core.impl.F f2 = ((androidx.camera.core.impl.q0) it3.next()).g;
                        List listUnmodifiableList = Collections.unmodifiableList(f2.a);
                        if (!listUnmodifiableList.isEmpty()) {
                            if (f2.a() != 0 && (iA = f2.a()) != 0) {
                                xK.m(A0.w0, Integer.valueOf(iA));
                            }
                            if (f2.b() != 0 && (iB = f2.b()) != 0) {
                                xK.m(A0.x0, Integer.valueOf(iB));
                            }
                            Iterator it4 = listUnmodifiableList.iterator();
                            while (it4.hasNext()) {
                                hashSet.add((androidx.camera.core.impl.J) it4.next());
                            }
                        }
                    }
                    if (hashSet.isEmpty()) {
                        AbstractC3053s1.h("Camera2CameraImpl", "Unable to find a repeating surface to attach to CaptureConfig");
                    }
                } else {
                    AbstractC3053s1.h("Camera2CameraImpl", "The capture config builder already has surface inside.");
                }
            }
            ArrayList arrayList4 = new ArrayList(hashSet);
            C0163c0 c0163c0A = C0163c0.a(xK);
            ArrayList arrayList5 = new ArrayList(arrayList2);
            v0 v0Var2 = v0.b;
            ArrayMap arrayMap2 = new ArrayMap();
            ArrayMap arrayMap3 = z.a;
            for (String str2 : arrayMap3.keySet()) {
                arrayMap2.put(str2, arrayMap3.get(str2));
            }
            arrayList.add(new androidx.camera.core.impl.F(arrayList4, c0163c0A, f.c, arrayList5, f.e, new v0(arrayMap2), interfaceC0177p2));
        }
        c.t("Issue capture request");
        c.l.j(arrayList);
    }

    public final long o() {
        this.w = this.u.getAndIncrement();
        ((C) this.f.b).K();
        return this.w;
    }
}

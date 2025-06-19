package androidx.activity;

import android.hardware.camera2.CameraDevice;
import android.os.Trace;
import android.view.MotionEvent;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.camera.camera2.internal.C0145w;
import androidx.camera.camera2.internal.T;
import androidx.camera.camera2.internal.V;
import androidx.camera.camera2.internal.k0;
import androidx.camera.core.S;
import androidx.camera.core.X;
import androidx.camera.core.g0;
import androidx.collection.C0223v;
import androidx.compose.ui.platform.C0971v;
import androidx.compose.ui.platform.O0;
import androidx.compose.ui.platform.P0;
import androidx.compose.ui.text.C0995g;
import com.comscore.streaming.EventType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;
import com.google.android.gms.internal.mlkit_vision_barcode.W4;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ScheduledFuture;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.activity.m, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final /* synthetic */ class RunnableC0041m implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ RunnableC0041m(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // java.lang.Runnable
    public final void run() {
        C0971v c0971v;
        char c;
        long j;
        C0223v c0223v;
        C0971v c0971v2;
        char c2;
        int i;
        C0223v c0223v2;
        int i2;
        char c3 = 7;
        int i3 = 0;
        boolean z = true;
        switch (this.a) {
            case 0:
                ViewTreeObserverOnDrawListenerC0042n viewTreeObserverOnDrawListenerC0042n = (ViewTreeObserverOnDrawListenerC0042n) this.b;
                Runnable runnable = viewTreeObserverOnDrawListenerC0042n.b;
                if (runnable != null) {
                    runnable.run();
                    viewTreeObserverOnDrawListenerC0042n.b = null;
                    return;
                }
                return;
            case 1:
                u.a((u) this.b);
                return;
            case 2:
                androidx.camera.camera2.internal.C c4 = (androidx.camera.camera2.internal.C) this.b;
                c4.u = false;
                c4.t = false;
                c4.t("OpenCameraConfigAndClose is done, state: ".concat(AbstractC0147y.l(c4.H)));
                int iK = AbstractC0147y.k(c4.H);
                if (iK == 1 || iK == 4) {
                    AbstractC3242q6.h(null, c4.m.isEmpty());
                    c4.u();
                    return;
                } else {
                    if (iK != 6) {
                        c4.t("OpenCameraConfigAndClose finished while in state: ".concat(AbstractC0147y.l(c4.H)));
                        return;
                    }
                    int i4 = c4.k;
                    if (i4 == 0) {
                        c4.J(false);
                        return;
                    } else {
                        c4.t("OpenCameraConfigAndClose in error: ".concat(androidx.camera.camera2.internal.C.v(i4)));
                        c4.h.b();
                        return;
                    }
                }
            case 3:
                ((CameraDevice) this.b).close();
                return;
            case 4:
                androidx.camera.camera2.internal.A a = (androidx.camera.camera2.internal.A) this.b;
                if (a.b) {
                    return;
                }
                AbstractC3242q6.h(null, ((androidx.camera.camera2.internal.B) a.d).f.H == 7 || ((androidx.camera.camera2.internal.B) a.d).f.H == 6);
                if (((androidx.camera.camera2.internal.B) a.d).c()) {
                    ((androidx.camera.camera2.internal.B) a.d).f.I(true);
                    return;
                } else {
                    ((androidx.camera.camera2.internal.B) a.d).f.J(true);
                    return;
                }
            case 5:
                V v = (V) this.b;
                synchronized (v.a) {
                    if (v.b.isEmpty()) {
                        return;
                    }
                    try {
                        v.i(v.b);
                        return;
                    } finally {
                        v.b.clear();
                    }
                }
            case 6:
                for (k0 k0Var : (LinkedHashSet) this.b) {
                    k0Var.getClass();
                    k0Var.c(k0Var);
                }
                return;
            case 7:
                ((androidx.camera.camera2.internal.compat.p) this.b).b.onCameraAccessPrioritiesChanged();
                return;
            case 8:
                androidx.camera.camera2.interop.c cVar = (androidx.camera.camera2.interop.c) this.b;
                androidx.concurrent.futures.i iVar = (androidx.concurrent.futures.i) cVar.g;
                if (iVar != null) {
                    iVar.b(null);
                    cVar.g = null;
                    return;
                }
                return;
            case 9:
                androidx.camera.core.H h = (androidx.camera.core.H) this.b;
                synchronized (h.u) {
                    try {
                        h.w = null;
                        androidx.camera.core.O o = h.v;
                        if (o != null) {
                            h.v = null;
                            h.f(o);
                        }
                    } catch (Throwable th) {
                        throw th;
                    }
                }
                return;
            case 10:
                ((X) this.b).n();
                return;
            case 11:
                ((androidx.work.impl.model.v) ((S) this.b).b).getClass();
                return;
            case 12:
                ((androidx.camera.core.imagecapture.d) this.b).c();
                return;
            case 13:
                C0145w c0145w = (C0145w) this.b;
                if (c0145w.c.H == 4) {
                    c0145w.c.J(false);
                    return;
                }
                return;
            case 14:
                com.airbnb.lottie.network.c cVar2 = (com.airbnb.lottie.network.c) this.b;
                if (((androidx.camera.camera2.internal.C) cVar2.b).H == 9) {
                    ((androidx.camera.camera2.internal.C) cVar2.b).B();
                    return;
                }
                return;
            case 15:
                ((androidx.concurrent.futures.l) this.b).cancel(true);
                return;
            case 16:
                ((ScheduledFuture) this.b).cancel(true);
                return;
            case 17:
                ((androidx.concurrent.futures.i) this.b).b(null);
                return;
            case 18:
                ((androidx.camera.core.processing.l) this.b).close();
                return;
            case 19:
                androidx.camera.core.processing.c cVar3 = (androidx.camera.core.processing.c) this.b;
                cVar3.j = true;
                cVar3.d();
                return;
            case 20:
                ((g0) this.b).a();
                return;
            case 21:
                ((androidx.camera.core.impl.J) this.b).b();
                return;
            case EventType.WINDOW_STATE /* 22 */:
                androidx.camera.core.processing.n nVar = (androidx.camera.core.processing.n) ((io.ktor.client.plugins.api.d) this.b).d;
                if (nVar != null) {
                    Iterator it2 = nVar.values().iterator();
                    while (it2.hasNext()) {
                        ((androidx.camera.core.processing.k) it2.next()).b();
                    }
                    return;
                }
                return;
            case EventType.AUDIO /* 23 */:
                androidx.camera.core.processing.concurrent.e eVar = (androidx.camera.core.processing.concurrent.e) this.b;
                eVar.f = true;
                eVar.d();
                return;
            case EventType.VIDEO /* 24 */:
                androidx.camera.core.processing.n nVar2 = (androidx.camera.core.processing.n) ((com.quizlet.data.repository.folderwithcreatorinclass.e) this.b).d;
                if (nVar2 != null) {
                    Iterator it3 = nVar2.values().iterator();
                    while (it3.hasNext()) {
                        ((androidx.camera.core.processing.k) it3.next()).b();
                    }
                    return;
                }
                return;
            case EventType.SUBS /* 25 */:
                ((T) this.b).k();
                return;
            case EventType.CDN /* 26 */:
                androidx.compose.material.ripple.j.setRippleState$lambda$2((androidx.compose.material.ripple.j) this.b);
                return;
            case 27:
                androidx.compose.ui.contentcapture.c cVar4 = (androidx.compose.ui.contentcapture.c) this.b;
                if (cVar4.c()) {
                    C0971v c0971v3 = cVar4.a;
                    c0971v3.q(true);
                    cVar4.h(c0971v3.getSemanticsOwner().a(), cVar4.o);
                    cVar4.f(c0971v3.getSemanticsOwner().a(), cVar4.o);
                    C0223v c0223vB = cVar4.b();
                    int[] iArr = c0223vB.b;
                    long[] jArr = c0223vB.a;
                    int length = jArr.length - 2;
                    C0223v c0223v3 = cVar4.n;
                    int i5 = 8;
                    if (length >= 0) {
                        int i6 = 0;
                        j = 255;
                        while (true) {
                            long j2 = jArr[i6];
                            boolean z2 = z;
                            if ((((~j2) << c3) & j2 & (-9187201950435737472L)) != -9187201950435737472L) {
                                int i7 = 8 - ((~(i6 - length)) >>> 31);
                                int i8 = i3;
                                while (i8 < i7) {
                                    if ((j2 & 255) < 128) {
                                        c2 = c3;
                                        int i9 = iArr[(i6 << 3) + i8];
                                        O0 o0 = (O0) c0223v3.e(i9);
                                        P0 p0 = (P0) c0223vB.e(i9);
                                        androidx.compose.ui.semantics.o oVar = p0 != null ? p0.a : null;
                                        if (oVar == null) {
                                            W4.g("no value for specified key");
                                            throw null;
                                        }
                                        i2 = i5;
                                        androidx.compose.ui.semantics.k kVar = oVar.d;
                                        int i10 = oVar.g;
                                        c0971v2 = c0971v3;
                                        LinkedHashMap linkedHashMap = kVar.a;
                                        if (o0 == null) {
                                            Iterator it4 = kVar.iterator();
                                            while (it4.hasNext()) {
                                                Object key = ((Map.Entry) it4.next()).getKey();
                                                Iterator it5 = it4;
                                                androidx.compose.ui.semantics.u uVar = androidx.compose.ui.semantics.r.u;
                                                if (Intrinsics.b(key, uVar)) {
                                                    Object obj = linkedHashMap.get(uVar);
                                                    if (obj == null) {
                                                        obj = null;
                                                    }
                                                    List list = (List) obj;
                                                    cVar4.g(i10, String.valueOf(list != null ? (C0995g) CollectionsKt.firstOrNull(list) : null));
                                                }
                                                it4 = it5;
                                            }
                                        } else {
                                            Iterator it6 = kVar.iterator();
                                            while (it6.hasNext()) {
                                                int i11 = i8;
                                                androidx.compose.ui.semantics.u uVar2 = (androidx.compose.ui.semantics.u) ((Map.Entry) it6.next()).getKey();
                                                C0223v c0223v4 = c0223vB;
                                                androidx.compose.ui.semantics.u uVar3 = androidx.compose.ui.semantics.r.u;
                                                if (Intrinsics.b(uVar2, uVar3)) {
                                                    Object obj2 = o0.a.a.get(uVar3);
                                                    if (obj2 == null) {
                                                        obj2 = null;
                                                    }
                                                    List list2 = (List) obj2;
                                                    C0995g c0995g = list2 != null ? (C0995g) CollectionsKt.firstOrNull(list2) : null;
                                                    Object obj3 = linkedHashMap.get(uVar3);
                                                    if (obj3 == null) {
                                                        obj3 = null;
                                                    }
                                                    List list3 = (List) obj3;
                                                    C0995g c0995g2 = list3 != null ? (C0995g) CollectionsKt.firstOrNull(list3) : null;
                                                    if (!Intrinsics.b(c0995g, c0995g2)) {
                                                        cVar4.g(i10, String.valueOf(c0995g2));
                                                    }
                                                }
                                                c0223vB = c0223v4;
                                                i8 = i11;
                                            }
                                        }
                                        i = i8;
                                        c0223v2 = c0223vB;
                                    } else {
                                        c0971v2 = c0971v3;
                                        c2 = c3;
                                        i = i8;
                                        c0223v2 = c0223vB;
                                        i2 = i5;
                                    }
                                    j2 >>= i2;
                                    i8 = i + 1;
                                    i5 = i2;
                                    c3 = c2;
                                    c0971v3 = c0971v2;
                                    c0223vB = c0223v2;
                                }
                                c0971v = c0971v3;
                                c = c3;
                                c0223v = c0223vB;
                                if (i7 == i5) {
                                }
                            } else {
                                c0971v = c0971v3;
                                c = c3;
                                c0223v = c0223vB;
                            }
                            if (i6 != length) {
                                i6++;
                                z = z2;
                                c3 = c;
                                c0971v3 = c0971v;
                                c0223vB = c0223v;
                                i3 = 0;
                                i5 = 8;
                            }
                        }
                    } else {
                        c0971v = c0971v3;
                        c = 7;
                        j = 255;
                    }
                    c0223v3.a();
                    C0223v c0223vB2 = cVar4.b();
                    int[] iArr2 = c0223vB2.b;
                    Object[] objArr = c0223vB2.c;
                    long[] jArr2 = c0223vB2.a;
                    int length2 = jArr2.length - 2;
                    if (length2 >= 0) {
                        int i12 = 0;
                        while (true) {
                            long j3 = jArr2[i12];
                            if ((((~j3) << c) & j3 & (-9187201950435737472L)) != -9187201950435737472L) {
                                int i13 = 8 - ((~(i12 - length2)) >>> 31);
                                for (int i14 = 0; i14 < i13; i14++) {
                                    if ((j3 & j) < 128) {
                                        int i15 = (i12 << 3) + i14;
                                        c0223v3.h(iArr2[i15], new O0(((P0) objArr[i15]).a, cVar4.b()));
                                    }
                                    j3 >>= 8;
                                }
                                if (i13 == 8) {
                                }
                            }
                            if (i12 != length2) {
                                i12++;
                            }
                        }
                    }
                    cVar4.o = new O0(c0971v.getSemanticsOwner().a(), cVar4.b());
                    cVar4.p = false;
                    return;
                }
                return;
            case 28:
                C0971v c0971v4 = (C0971v) this.b;
                c0971v4.D1 = false;
                MotionEvent motionEvent = c0971v4.x1;
                Intrinsics.d(motionEvent);
                if (motionEvent.getActionMasked() != 10) {
                    throw new IllegalStateException("The ACTION_HOVER_EXIT event was not cleared.");
                }
                c0971v4.D(motionEvent);
                return;
            default:
                androidx.compose.ui.platform.F f = (androidx.compose.ui.platform.F) this.b;
                Trace.beginSection("measureAndLayout");
                try {
                    f.d.q(true);
                    Unit unit = Unit.a;
                    Trace.endSection();
                    Trace.beginSection("checkForSemanticsChanges");
                    try {
                        f.n();
                        Trace.endSection();
                        f.J = false;
                        return;
                    } finally {
                    }
                } finally {
                }
        }
    }
}

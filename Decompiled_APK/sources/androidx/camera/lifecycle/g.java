package androidx.camera.lifecycle;

import android.content.Context;
import android.os.Trace;
import androidx.camera.camera2.internal.C0138o;
import androidx.camera.core.C0192o;
import androidx.camera.core.C0194q;
import androidx.camera.core.C0195s;
import androidx.camera.core.InterfaceC0191n;
import androidx.camera.core.Q;
import androidx.camera.core.impl.AbstractC0180t;
import androidx.camera.core.impl.C0164d;
import androidx.camera.core.impl.C0179s;
import androidx.camera.core.impl.D;
import androidx.camera.core.impl.InterfaceC0183w;
import androidx.camera.core.impl.InterfaceC0185y;
import androidx.camera.core.impl.K;
import androidx.camera.core.impl.k0;
import androidx.camera.core.impl.utils.futures.k;
import androidx.camera.core.l0;
import androidx.concurrent.futures.l;
import androidx.lifecycle.J;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;
import com.google.android.gms.internal.mlkit_vision_barcode.S;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3359k2;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import kotlin.Unit;
import kotlin.collections.B;
import kotlin.collections.C4933y;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class g {
    public static final g i = new g();
    public final Object a = new Object();
    public e b;
    public l c;
    public final k d;
    public final com.quizlet.data.repository.studysetwithcreatorinclass.g e;
    public C0194q f;
    public Context g;
    public final HashMap h;

    public g() {
        k kVar = k.c;
        Intrinsics.checkNotNullExpressionValue(kVar, "immediateFuture<Void>(null)");
        this.d = kVar;
        this.e = new com.quizlet.data.repository.studysetwithcreatorinclass.g(1);
        this.h = new HashMap();
    }

    public static final void a(g gVar, C0195s c0195s) {
        gVar.getClass();
        Trace.beginSection(AbstractC3359k2.f("CX:configureInstanceInternal"));
        try {
            synchronized (gVar.a) {
                AbstractC3242q6.h("CameraX has already been configured. To use a different configuration, shutdown() must be called.", gVar.b == null);
                gVar.b = new e(c0195s);
                Unit unit = Unit.a;
            }
        } finally {
            Trace.endSection();
        }
    }

    public static final C0179s b(g gVar, C0192o c0192o) {
        gVar.getClass();
        Iterator it2 = c0192o.a.iterator();
        while (it2.hasNext()) {
            Object next = it2.next();
            Intrinsics.checkNotNullExpressionValue(next, "cameraSelector.cameraFilterSet");
            ((InterfaceC0191n) next).getClass();
            C0164d c0164d = InterfaceC0191n.a;
            if (!Intrinsics.b(c0164d, c0164d)) {
                synchronized (K.a) {
                }
                Intrinsics.d(gVar.g);
            }
        }
        return AbstractC0180t.a;
    }

    public static final void c(g gVar, int i2) {
        C0194q c0194q = gVar.f;
        if (c0194q == null) {
            return;
        }
        C0138o c0138o = c0194q.f;
        if (c0138o == null) {
            throw new IllegalStateException("CameraX not initialized yet.");
        }
        androidx.camera.camera2.internal.concurrent.a aVar = (androidx.camera.camera2.internal.concurrent.a) c0138o.c;
        if (i2 != aVar.b) {
            Iterator it2 = ((ArrayList) aVar.c).iterator();
            while (it2.hasNext()) {
                D d = (D) it2.next();
                int i3 = aVar.b;
                synchronized (d.b) {
                    boolean z = true;
                    d.c = i2 == 2 ? 2 : 1;
                    boolean z2 = i3 != 2 && i2 == 2;
                    if (i3 != 2 || i2 == 2) {
                        z = false;
                    }
                    if (z2 || z) {
                        d.b();
                    }
                }
            }
        }
        if (aVar.b == 2 && i2 != 2) {
            ((ArrayList) aVar.d).clear();
        }
        aVar.b = i2;
    }

    public final void d(J lifecycleOwner, C0192o cameraSelector, l0... useCases) {
        int i2;
        Intrinsics.checkNotNullParameter(lifecycleOwner, "lifecycleOwner");
        Intrinsics.checkNotNullParameter(cameraSelector, "cameraSelector");
        Intrinsics.checkNotNullParameter(useCases, "useCases");
        Trace.beginSection(AbstractC3359k2.f("CX:bindToLifecycle"));
        try {
            C0194q c0194q = this.f;
            if (c0194q == null) {
                i2 = 0;
            } else {
                C0138o c0138o = c0194q.f;
                if (c0138o == null) {
                    throw new IllegalStateException("CameraX not initialized yet.");
                }
                i2 = ((androidx.camera.camera2.internal.concurrent.a) c0138o.c).b;
            }
            if (i2 == 2) {
                throw new UnsupportedOperationException("bindToLifecycle for single camera is not supported in concurrent camera mode, call unbindAll() first");
            }
            c(this, 1);
            Q DEFAULT = Q.a;
            Intrinsics.checkNotNullExpressionValue(DEFAULT, "DEFAULT");
            Intrinsics.checkNotNullExpressionValue(DEFAULT, "DEFAULT");
            e(lifecycleOwner, cameraSelector, kotlin.collections.K.a, (l0[]) Arrays.copyOf(useCases, useCases.length));
        } finally {
            Trace.endSection();
        }
    }

    public final b e(J lifecycleOwner, C0192o primaryCameraSelector, kotlin.collections.K effects, l0... useCases) {
        b bVarG;
        Collection collectionUnmodifiableCollection;
        boolean zContains;
        Q secondaryLayoutSettings = Q.a;
        Intrinsics.checkNotNullParameter(lifecycleOwner, "lifecycleOwner");
        Intrinsics.checkNotNullParameter(primaryCameraSelector, "primaryCameraSelector");
        Intrinsics.checkNotNullParameter(secondaryLayoutSettings, "primaryLayoutSettings");
        Intrinsics.checkNotNullParameter(secondaryLayoutSettings, "secondaryLayoutSettings");
        Intrinsics.checkNotNullParameter(effects, "effects");
        Intrinsics.checkNotNullParameter(useCases, "useCases");
        Trace.beginSection(AbstractC3359k2.f("CX:bindToLifecycle-internal"));
        try {
            S.d();
            C0194q c0194q = this.f;
            Intrinsics.d(c0194q);
            InterfaceC0185y interfaceC0185yC = primaryCameraSelector.c(c0194q.a.k());
            Intrinsics.checkNotNullExpressionValue(interfaceC0185yC, "primaryCameraSelector.se…cameraRepository.cameras)");
            interfaceC0185yC.m(true);
            k0 k0VarF = f(primaryCameraSelector);
            com.quizlet.data.repository.studysetwithcreatorinclass.g gVar = this.e;
            androidx.camera.core.internal.a aVarT = androidx.camera.core.internal.g.t(k0VarF, null);
            synchronized (gVar.b) {
                bVarG = (b) ((HashMap) gVar.c).get(new a(lifecycleOwner, aVarT));
            }
            com.quizlet.data.repository.studysetwithcreatorinclass.g gVar2 = this.e;
            synchronized (gVar2.b) {
                collectionUnmodifiableCollection = Collections.unmodifiableCollection(((HashMap) gVar2.c).values());
            }
            Iterator it2 = C4933y.z(useCases).iterator();
            while (it2.hasNext()) {
                l0 l0Var = (l0) it2.next();
                for (Object lifecycleCameras : collectionUnmodifiableCollection) {
                    Intrinsics.checkNotNullExpressionValue(lifecycleCameras, "lifecycleCameras");
                    b bVar = (b) lifecycleCameras;
                    synchronized (bVar.a) {
                        zContains = ((ArrayList) bVar.c.w()).contains(l0Var);
                    }
                    if (zContains && !bVar.equals(bVarG)) {
                        String str = String.format("Use case %s already bound to a different lifecycle.", Arrays.copyOf(new Object[]{l0Var}, 1));
                        Intrinsics.checkNotNullExpressionValue(str, "format(format, *args)");
                        throw new IllegalStateException(str);
                    }
                }
            }
            if (bVarG == null) {
                com.quizlet.data.repository.studysetwithcreatorinclass.g gVar3 = this.e;
                C0194q c0194q2 = this.f;
                Intrinsics.d(c0194q2);
                C0138o c0138o = c0194q2.f;
                if (c0138o == null) {
                    throw new IllegalStateException("CameraX not initialized yet.");
                }
                androidx.camera.camera2.internal.concurrent.a aVar = (androidx.camera.camera2.internal.concurrent.a) c0138o.c;
                C0194q c0194q3 = this.f;
                Intrinsics.d(c0194q3);
                com.quizlet.data.repository.activitycenter.b bVar2 = c0194q3.g;
                if (bVar2 == null) {
                    throw new IllegalStateException("CameraX not initialized yet.");
                }
                C0194q c0194q4 = this.f;
                Intrinsics.d(c0194q4);
                androidx.camera.camera2.internal.K k = c0194q4.h;
                if (k == null) {
                    throw new IllegalStateException("CameraX not initialized yet.");
                }
                bVarG = gVar3.g(lifecycleOwner, new androidx.camera.core.internal.g(interfaceC0185yC, null, k0VarF, null, aVar, bVar2, k));
            }
            if (useCases.length != 0) {
                com.quizlet.data.repository.studysetwithcreatorinclass.g gVar4 = this.e;
                List listJ = B.j(Arrays.copyOf(useCases, useCases.length));
                C0194q c0194q5 = this.f;
                Intrinsics.d(c0194q5);
                C0138o c0138o2 = c0194q5.f;
                if (c0138o2 == null) {
                    throw new IllegalStateException("CameraX not initialized yet.");
                }
                gVar4.b(bVarG, effects, listJ, (androidx.camera.camera2.internal.concurrent.a) c0138o2.c);
            }
            return bVarG;
        } finally {
            Trace.endSection();
        }
    }

    public final k0 f(C0192o cameraSelector) {
        Object k0Var;
        Intrinsics.checkNotNullParameter(cameraSelector, "cameraSelector");
        Trace.beginSection(AbstractC3359k2.f("CX:getCameraInfo"));
        try {
            C0194q c0194q = this.f;
            Intrinsics.d(c0194q);
            InterfaceC0183w interfaceC0183wN = cameraSelector.c(c0194q.a.k()).n();
            Intrinsics.checkNotNullExpressionValue(interfaceC0183wN, "cameraSelector.select(mC…meras).cameraInfoInternal");
            C0179s c0179sB = b(this, cameraSelector);
            androidx.camera.core.internal.a aVar = new androidx.camera.core.internal.a(interfaceC0183wN.c(), c0179sB.a);
            Intrinsics.checkNotNullExpressionValue(aVar, "create(\n                …ilityId\n                )");
            synchronized (this.a) {
                try {
                    k0Var = this.h.get(aVar);
                    if (k0Var == null) {
                        k0Var = new k0(interfaceC0183wN, c0179sB);
                        this.h.put(aVar, k0Var);
                    }
                    Unit unit = Unit.a;
                } catch (Throwable th) {
                    throw th;
                }
            }
            return (k0) k0Var;
        } finally {
            Trace.endSection();
        }
    }
}

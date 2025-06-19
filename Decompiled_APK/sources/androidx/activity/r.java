package androidx.activity;

import android.graphics.SurfaceTexture;
import android.graphics.Typeface;
import android.hardware.camera2.TotalCaptureResult;
import android.util.ArrayMap;
import android.util.LongSparseArray;
import android.util.Size;
import android.view.Surface;
import androidx.appcompat.app.ExecutorC0060p;
import androidx.camera.camera2.internal.C0128e;
import androidx.camera.camera2.internal.C0134k;
import androidx.camera.camera2.internal.C0135l;
import androidx.camera.camera2.internal.C0137n;
import androidx.camera.camera2.internal.C0143u;
import androidx.camera.camera2.internal.InterfaceC0136m;
import androidx.camera.camera2.internal.c0;
import androidx.camera.core.C0156h;
import androidx.camera.core.W;
import androidx.camera.core.a0;
import androidx.camera.core.impl.AbstractC0171j;
import androidx.camera.core.impl.Q;
import androidx.camera.core.impl.U;
import androidx.camera.core.impl.V;
import androidx.camera.core.impl.o0;
import androidx.camera.core.impl.q0;
import androidx.camera.core.impl.x0;
import androidx.camera.core.j0;
import androidx.credentials.exceptions.ClearCredentialUnknownException;
import androidx.credentials.exceptions.GetCredentialUnknownException;
import androidx.credentials.playservices.controllers.BeginSignIn.CredentialProviderBeginSignInController;
import androidx.lifecycle.Y;
import com.comscore.streaming.EventType;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.google.android.gms.internal.mlkit_vision_barcode.T;
import com.google.android.gms.internal.mlkit_vision_barcode.Y5;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes.dex */
public final /* synthetic */ class r implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;

    public /* synthetic */ r(int i, Object obj, Object obj2) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                s sVar = (s) this.b;
                sVar.getLifecycle().a(new C0036h(0, (L) this.c, sVar));
                return;
            case 1:
                Runnable runnable = (Runnable) this.c;
                ExecutorC0060p executorC0060p = (ExecutorC0060p) this.b;
                executorC0060p.getClass();
                try {
                    runnable.run();
                    return;
                } finally {
                    executorC0060p.a();
                }
            case 2:
                C0137n c0137n = (C0137n) this.b;
                androidx.camera.core.impl.utils.futures.i.e(true, Y5.b(new C0128e(c0137n, c0137n.o(), 0)), (androidx.concurrent.futures.i) this.c, T.a());
                return;
            case 3:
                C0134k c0134k = ((C0137n) this.b).x;
                HashSet hashSet = (HashSet) c0134k.b;
                AbstractC0171j abstractC0171j = (AbstractC0171j) this.c;
                hashSet.remove(abstractC0171j);
                ((ArrayMap) c0134k.c).remove(abstractC0171j);
                return;
            case 4:
                C0135l c0135l = (C0135l) this.b;
                HashSet hashSet2 = new HashSet();
                HashSet hashSet3 = (HashSet) c0135l.b;
                Iterator it2 = hashSet3.iterator();
                while (it2.hasNext()) {
                    InterfaceC0136m interfaceC0136m = (InterfaceC0136m) it2.next();
                    if (interfaceC0136m.d((TotalCaptureResult) this.c)) {
                        hashSet2.add(interfaceC0136m);
                    }
                }
                if (hashSet2.isEmpty()) {
                    return;
                }
                hashSet3.removeAll(hashSet2);
                return;
            case 5:
                ((o0) this.b).a((q0) this.c);
                return;
            case 6:
                ((Surface) this.b).release();
                ((SurfaceTexture) this.c).release();
                return;
            case 7:
                androidx.camera.camera2.internal.C c = (androidx.camera.camera2.internal.C) this.b;
                c0 c0Var = c.w;
                androidx.concurrent.futures.i iVar = (androidx.concurrent.futures.i) this.c;
                if (c0Var == null) {
                    iVar.b(Boolean.FALSE);
                    return;
                } else {
                    iVar.b(Boolean.valueOf(c.a.d(androidx.camera.camera2.internal.C.w(c0Var))));
                    return;
                }
            case 8:
                androidx.camera.camera2.internal.C c2 = (androidx.camera.camera2.internal.C) this.b;
                c2.getClass();
                StringBuilder sb = new StringBuilder("Use case ");
                String str = (String) this.c;
                sb.append(str);
                sb.append(" INACTIVE");
                c2.t(sb.toString());
                LinkedHashMap linkedHashMap = c2.a.a;
                if (linkedHashMap.containsKey(str)) {
                    x0 x0Var = (x0) linkedHashMap.get(str);
                    x0Var.f = false;
                    if (!x0Var.e) {
                        linkedHashMap.remove(str);
                    }
                }
                c2.K();
                return;
            case 9:
                com.bumptech.glide.manager.p pVar = (com.bumptech.glide.manager.p) this.b;
                pVar.getClass();
                ((Q) this.c).e(pVar);
                return;
            case 10:
                ((a0) this.b).g();
                a0 a0Var = (a0) this.c;
                if (a0Var != null) {
                    a0Var.g();
                    return;
                }
                return;
            case 11:
                androidx.camera.core.T t = (androidx.camera.core.T) this.b;
                t.getClass();
                ((Q) this.c).e(t);
                return;
            case 12:
                ((W) this.b).a((j0) this.c);
                return;
            case 13:
                androidx.camera.core.impl.J j = (androidx.camera.core.impl.J) this.b;
                String str2 = (String) this.c;
                j.getClass();
                try {
                    j.e.get();
                    androidx.camera.core.impl.J.n.decrementAndGet();
                    androidx.camera.core.impl.J.m.get();
                    j.e();
                    return;
                } catch (Exception e) {
                    AbstractC3053s1.c("DeferrableSurface", "Unexpected surface termination for " + j + "\nStack Trace:\n" + str2);
                    synchronized (j.a) {
                        throw new IllegalArgumentException(String.format("DeferrableSurface %s [closed: %b, use_count: %s] terminated with unexpected exception.", j, Boolean.valueOf(j.c), Integer.valueOf(j.b)), e);
                    }
                }
            case 14:
                ((Y) ((com.quizlet.data.repository.activitycenter.b) this.b).b).k((U) this.c);
                return;
            case 15:
                U u = (U) this.b;
                if (u.a.get()) {
                    V v = (V) this.c;
                    v.getClass();
                    u.b.k(v.a);
                    return;
                }
                return;
            case 16:
                androidx.camera.core.processing.c cVar = (androidx.camera.core.processing.c) this.b;
                androidx.camera.core.impl.utils.executor.e eVar = cVar.c;
                androidx.camera.core.processing.l lVar = (androidx.camera.core.processing.l) this.c;
                Surface surfaceD = lVar.d(eVar, new androidx.camera.core.internal.e(1, cVar, lVar));
                cVar.a.o(surfaceD);
                cVar.h.put(lVar, surfaceD);
                return;
            case 17:
                final androidx.camera.core.processing.c cVar2 = (androidx.camera.core.processing.c) this.b;
                cVar2.i++;
                androidx.camera.core.processing.e eVar2 = cVar2.a;
                androidx.camera.core.processing.util.i.d((AtomicBoolean) eVar2.c, true);
                androidx.camera.core.processing.util.i.c((Thread) eVar2.e);
                final SurfaceTexture surfaceTexture = new SurfaceTexture(eVar2.a);
                final j0 j0Var = (j0) this.c;
                Size size = j0Var.b;
                surfaceTexture.setDefaultBufferSize(size.getWidth(), size.getHeight());
                final Surface surface = new Surface(surfaceTexture);
                C0143u c0143u = new C0143u(8, cVar2, j0Var);
                androidx.camera.core.impl.utils.executor.e eVar3 = cVar2.c;
                j0Var.b(eVar3, c0143u);
                j0Var.a(surface, eVar3, new androidx.core.util.a() { // from class: androidx.camera.core.processing.b
                    @Override // androidx.core.util.a
                    public final void accept(Object obj) {
                        c cVar3 = cVar2;
                        j0 j0Var2 = j0Var;
                        SurfaceTexture surfaceTexture2 = surfaceTexture;
                        Surface surface2 = surface;
                        cVar3.getClass();
                        synchronized (j0Var2.a) {
                            j0Var2.m = null;
                            j0Var2.n = null;
                        }
                        surfaceTexture2.setOnFrameAvailableListener(null);
                        surfaceTexture2.release();
                        surface2.release();
                        cVar3.i--;
                        cVar3.d();
                    }
                });
                surfaceTexture.setOnFrameAvailableListener(cVar2, cVar2.d);
                return;
            case 18:
                androidx.camera.core.processing.l lVar2 = (androidx.camera.core.processing.l) this.b;
                lVar2.getClass();
                ((androidx.core.util.a) ((AtomicReference) this.c).get()).accept(new C0156h(lVar2));
                return;
            case 19:
                final androidx.camera.core.processing.concurrent.e eVar4 = (androidx.camera.core.processing.concurrent.e) this.b;
                eVar4.e++;
                j0 j0Var2 = (j0) this.c;
                androidx.camera.core.processing.concurrent.c cVar3 = eVar4.a;
                androidx.camera.core.processing.util.i.d((AtomicBoolean) cVar3.c, true);
                androidx.camera.core.processing.util.i.c((Thread) cVar3.e);
                boolean z = j0Var2.e;
                final SurfaceTexture surfaceTexture2 = new SurfaceTexture(z ? cVar3.n : cVar3.o);
                Size size2 = j0Var2.b;
                surfaceTexture2.setDefaultBufferSize(size2.getWidth(), size2.getHeight());
                final Surface surface2 = new Surface(surfaceTexture2);
                j0Var2.a(surface2, eVar4.c, new androidx.core.util.a() { // from class: androidx.camera.core.processing.concurrent.d
                    @Override // androidx.core.util.a
                    public final void accept(Object obj) {
                        e eVar5 = eVar4;
                        eVar5.getClass();
                        SurfaceTexture surfaceTexture3 = surfaceTexture2;
                        surfaceTexture3.setOnFrameAvailableListener(null);
                        surfaceTexture3.release();
                        surface2.release();
                        eVar5.e--;
                        eVar5.d();
                    }
                });
                if (z) {
                    eVar4.i = surfaceTexture2;
                    return;
                } else {
                    eVar4.j = surfaceTexture2;
                    surfaceTexture2.setOnFrameAvailableListener(eVar4, eVar4.d);
                    return;
                }
            case 20:
                androidx.camera.core.processing.concurrent.e eVar5 = (androidx.camera.core.processing.concurrent.e) this.b;
                androidx.camera.core.impl.utils.executor.e eVar6 = eVar5.c;
                androidx.camera.core.processing.l lVar3 = (androidx.camera.core.processing.l) this.c;
                Surface surfaceD2 = lVar3.d(eVar6, new androidx.camera.core.internal.e(2, eVar5, lVar3));
                eVar5.a.o(surfaceD2);
                eVar5.h.put(lVar3, surfaceD2);
                return;
            case 21:
                ((androidx.camera.view.e) this.b).a.l.a((j0) this.c);
                return;
            case EventType.WINDOW_STATE /* 22 */:
                androidx.camera.view.s sVar2 = (androidx.camera.view.s) this.b;
                j0 j0Var3 = sVar2.h;
                if (j0Var3 != null && j0Var3 == ((j0) this.c)) {
                    sVar2.h = null;
                    sVar2.g = null;
                }
                androidx.camera.camera2.internal.T t2 = sVar2.l;
                if (t2 != null) {
                    t2.k();
                    sVar2.l = null;
                    return;
                }
                return;
            case EventType.AUDIO /* 23 */:
                androidx.compose.ui.contentcapture.a.a((androidx.compose.ui.contentcapture.c) this.b, (LongSparseArray) this.c);
                return;
            case EventType.VIDEO /* 24 */:
                ((androidx.core.content.res.b) this.b).j((Typeface) this.c);
                return;
            case EventType.SUBS /* 25 */:
                ((androidx.credentials.e) this.b).b(((kotlin.jvm.internal.J) this.c).a);
                return;
            case EventType.CDN /* 26 */:
                ((androidx.credentials.e) this.b).b(new ClearCredentialUnknownException(((Exception) this.c).getMessage()));
                return;
            case 27:
                ((CredentialProviderBeginSignInController) this.b).f().onResult((androidx.credentials.p) this.c);
                return;
            case 28:
                ((CredentialProviderBeginSignInController) this.b).f().b(((kotlin.jvm.internal.J) this.c).a);
                return;
            default:
                ((CredentialProviderBeginSignInController) this.b).f().b((GetCredentialUnknownException) this.c);
                return;
        }
    }
}

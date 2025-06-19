package androidx.camera.core;

import android.util.Range;
import android.util.Size;
import android.view.Surface;
import androidx.camera.camera2.internal.C0143u;
import androidx.camera.core.impl.C0168g;
import androidx.camera.core.impl.DeferrableSurface$SurfaceUnavailableException;
import androidx.camera.core.impl.InterfaceC0185y;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;
import com.google.android.gms.internal.mlkit_vision_barcode.Y5;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes.dex */
public final class j0 {
    public final Object a = new Object();
    public final Size b;
    public final C0196t c;
    public final InterfaceC0185y d;
    public final boolean e;
    public final androidx.concurrent.futures.l f;
    public final androidx.concurrent.futures.i g;
    public final androidx.concurrent.futures.l h;
    public final androidx.concurrent.futures.i i;
    public final androidx.concurrent.futures.i j;
    public final g0 k;
    public C0187j l;
    public i0 m;
    public Executor n;

    static {
        Range range = C0168g.f;
    }

    public j0(Size size, InterfaceC0185y interfaceC0185y, boolean z, C0196t c0196t, androidx.camera.core.processing.f fVar) {
        this.b = size;
        this.d = interfaceC0185y;
        this.e = z;
        this.c = c0196t;
        final String str = "SurfaceRequest[size: " + size + ", id: " + hashCode() + "]";
        final AtomicReference atomicReference = new AtomicReference(null);
        final int i = 0;
        androidx.concurrent.futures.l lVarB = Y5.b(new androidx.concurrent.futures.j() { // from class: androidx.camera.core.d0
            @Override // androidx.concurrent.futures.j
            public final Object d(androidx.concurrent.futures.i iVar) {
                switch (i) {
                    case 0:
                        atomicReference.set(iVar);
                        return android.support.v4.media.session.a.t(new StringBuilder(), str, "-cancellation");
                    case 1:
                        atomicReference.set(iVar);
                        return android.support.v4.media.session.a.t(new StringBuilder(), str, "-status");
                    default:
                        atomicReference.set(iVar);
                        return android.support.v4.media.session.a.t(new StringBuilder(), str, "-Surface");
                }
            }
        });
        androidx.concurrent.futures.i iVar = (androidx.concurrent.futures.i) atomicReference.get();
        iVar.getClass();
        this.j = iVar;
        final AtomicReference atomicReference2 = new AtomicReference(null);
        final int i2 = 1;
        androidx.concurrent.futures.l lVarB2 = Y5.b(new androidx.concurrent.futures.j() { // from class: androidx.camera.core.d0
            @Override // androidx.concurrent.futures.j
            public final Object d(androidx.concurrent.futures.i iVar2) {
                switch (i2) {
                    case 0:
                        atomicReference2.set(iVar2);
                        return android.support.v4.media.session.a.t(new StringBuilder(), str, "-cancellation");
                    case 1:
                        atomicReference2.set(iVar2);
                        return android.support.v4.media.session.a.t(new StringBuilder(), str, "-status");
                    default:
                        atomicReference2.set(iVar2);
                        return android.support.v4.media.session.a.t(new StringBuilder(), str, "-Surface");
                }
            }
        });
        this.h = lVarB2;
        lVarB2.a(new androidx.camera.core.impl.utils.futures.h(0, lVarB2, new androidx.work.impl.model.e(2, iVar, lVarB)), com.google.android.gms.internal.mlkit_vision_barcode.T.a());
        androidx.concurrent.futures.i iVar2 = (androidx.concurrent.futures.i) atomicReference2.get();
        iVar2.getClass();
        final AtomicReference atomicReference3 = new AtomicReference(null);
        final int i3 = 2;
        androidx.concurrent.futures.l lVarB3 = Y5.b(new androidx.concurrent.futures.j() { // from class: androidx.camera.core.d0
            @Override // androidx.concurrent.futures.j
            public final Object d(androidx.concurrent.futures.i iVar22) {
                switch (i3) {
                    case 0:
                        atomicReference3.set(iVar22);
                        return android.support.v4.media.session.a.t(new StringBuilder(), str, "-cancellation");
                    case 1:
                        atomicReference3.set(iVar22);
                        return android.support.v4.media.session.a.t(new StringBuilder(), str, "-status");
                    default:
                        atomicReference3.set(iVar22);
                        return android.support.v4.media.session.a.t(new StringBuilder(), str, "-Surface");
                }
            }
        });
        this.f = lVarB3;
        androidx.concurrent.futures.i iVar3 = (androidx.concurrent.futures.i) atomicReference3.get();
        iVar3.getClass();
        this.g = iVar3;
        g0 g0Var = new g0(this, size);
        this.k = g0Var;
        com.google.common.util.concurrent.e eVarD = androidx.camera.core.impl.utils.futures.i.d(g0Var.e);
        lVarB3.a(new androidx.camera.core.impl.utils.futures.h(0, lVarB3, new com.quizlet.data.repository.folderwithcreator.e(eVarD, iVar2, str, 1)), com.google.android.gms.internal.mlkit_vision_barcode.T.a());
        eVarD.a(new e0(this, 0), com.google.android.gms.internal.mlkit_vision_barcode.T.a());
        androidx.camera.core.impl.utils.executor.a aVarA = com.google.android.gms.internal.mlkit_vision_barcode.T.a();
        AtomicReference atomicReference4 = new AtomicReference(null);
        androidx.concurrent.futures.l lVarB4 = Y5.b(new C0143u(5, this, atomicReference4));
        lVarB4.a(new androidx.camera.core.impl.utils.futures.h(0, lVarB4, new com.google.firebase.platforminfo.c(fVar)), aVarA);
        androidx.concurrent.futures.i iVar4 = (androidx.concurrent.futures.i) atomicReference4.get();
        iVar4.getClass();
        this.i = iVar4;
    }

    public final void a(final Surface surface, Executor executor, final androidx.core.util.a aVar) {
        if (!this.g.b(surface)) {
            androidx.concurrent.futures.l lVar = this.f;
            if (!lVar.isCancelled()) {
                AbstractC3242q6.h(null, lVar.b.isDone());
                try {
                    lVar.get();
                    final int i = 0;
                    executor.execute(new Runnable() { // from class: androidx.camera.core.f0
                        @Override // java.lang.Runnable
                        public final void run() {
                            switch (i) {
                                case 0:
                                    aVar.accept(new C0157i(3, surface));
                                    break;
                                default:
                                    aVar.accept(new C0157i(4, surface));
                                    break;
                            }
                        }
                    });
                    return;
                } catch (InterruptedException | ExecutionException unused) {
                    final int i2 = 1;
                    executor.execute(new Runnable() { // from class: androidx.camera.core.f0
                        @Override // java.lang.Runnable
                        public final void run() {
                            switch (i2) {
                                case 0:
                                    aVar.accept(new C0157i(3, surface));
                                    break;
                                default:
                                    aVar.accept(new C0157i(4, surface));
                                    break;
                            }
                        }
                    });
                    return;
                }
            }
        }
        androidx.work.impl.model.l lVar2 = new androidx.work.impl.model.l(aVar, false, surface, 2);
        androidx.concurrent.futures.l lVar3 = this.h;
        lVar3.a(new androidx.camera.core.impl.utils.futures.h(0, lVar3, lVar2), executor);
    }

    public final void b(Executor executor, i0 i0Var) {
        C0187j c0187j;
        synchronized (this.a) {
            this.m = i0Var;
            this.n = executor;
            c0187j = this.l;
        }
        if (c0187j != null) {
            executor.execute(new c0(i0Var, c0187j, 1));
        }
    }

    public final void c() {
        this.g.d(new DeferrableSurface$SurfaceUnavailableException("Surface request will not complete."));
    }
}

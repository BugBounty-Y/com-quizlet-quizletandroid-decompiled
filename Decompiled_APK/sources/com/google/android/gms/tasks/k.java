package com.google.android.gms.tasks;

import android.os.Trace;
import android.util.Size;
import androidx.camera.camera2.internal.C0132i;
import androidx.camera.core.A;
import androidx.camera.core.D;
import androidx.camera.core.W;
import androidx.camera.core.impl.C0162c;
import androidx.camera.core.impl.C0163c0;
import androidx.camera.core.impl.C0165d0;
import androidx.camera.core.impl.M;
import androidx.camera.core.impl.P;
import androidx.camera.core.impl.X;
import com.amazon.device.ads.DtbConstants;
import com.google.android.gms.common.internal.u;
import com.google.android.gms.internal.mlkit_vision_barcode.S;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3359k2;
import com.google.firebase.messaging.p;
import com.google.mlkit.common.MlKitException;
import java.lang.ref.WeakReference;
import java.util.concurrent.Callable;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicReference;
import kotlin.Unit;
import kotlinx.coroutines.E;

/* loaded from: classes2.dex */
public final class k implements Runnable {
    public final /* synthetic */ int a;
    public Object b;
    public final Object c;

    public /* synthetic */ k(int i, Object obj, Object obj2) {
        this.a = i;
        this.b = obj2;
        this.c = obj;
    }

    private final void a() {
        com.google.android.material.floatingactionbutton.c cVar = (com.google.android.material.floatingactionbutton.c) this.b;
        androidx.camera.lifecycle.g gVar = (androidx.camera.lifecycle.g) this.c;
        gVar.getClass();
        Trace.beginSection(AbstractC3359k2.f("CX:unbindAll"));
        try {
            S.d();
            androidx.camera.lifecycle.g.c(gVar, 0);
            gVar.e.w();
            Unit unit = Unit.a;
            Trace.endSection();
            ((com.google.mlkit.vision.camera.a) cVar.b).f.getClass();
            ((com.google.mlkit.vision.camera.a) cVar.b).f.getClass();
            Size size = new Size(DtbConstants.DEFAULT_PLAYER_HEIGHT, 360);
            androidx.camera.camera2.impl.a aVar = new androidx.camera.camera2.impl.a(1);
            C0162c c0162c = P.h0;
            aVar.b.m(c0162c, size);
            aVar.b.m(M.b, 0);
            M m = new M(C0163c0.a(aVar.b));
            P.u(m);
            A a = new A(m);
            com.google.mlkit.vision.camera.a aVar2 = (com.google.mlkit.vision.camera.a) cVar.b;
            com.google.mlkit.vision.camera.internal.a aVar3 = aVar2.a;
            p pVar = aVar2.b;
            synchronized (a.p) {
                try {
                    D d = a.o;
                    C0132i c0132i = new C0132i(pVar, 4);
                    synchronized (d.r) {
                        d.a = c0132i;
                        d.g = aVar3;
                    }
                    if (a.q == null) {
                        a.m();
                    }
                    a.q = pVar;
                } catch (Throwable th) {
                    throw th;
                }
            }
            WeakReference weakReference = ((com.google.mlkit.vision.camera.a) cVar.b).j;
            if (weakReference == null || weakReference.get() == null) {
                WeakReference weakReference2 = ((com.google.mlkit.vision.camera.a) cVar.b).j;
                if (weakReference2 != null && weakReference2.get() == null) {
                    cVar.onFailure(new IllegalStateException("The SurfaceProvider has been destroyed."));
                    return;
                }
                com.google.mlkit.vision.camera.a aVar4 = (com.google.mlkit.vision.camera.a) cVar.b;
                gVar.d(aVar4, aVar4.c, a);
                ((com.google.mlkit.vision.camera.a) cVar.b).d(1);
                return;
            }
            com.google.android.gms.internal.instantapps.a aVar5 = new com.google.android.gms.internal.instantapps.a(6);
            ((X) aVar5.b).m(c0162c, size);
            C0165d0 c0165d0 = new C0165d0(C0163c0.a((X) aVar5.b));
            P.u(c0165d0);
            androidx.camera.core.X x = new androidx.camera.core.X(c0165d0);
            x.p = androidx.camera.core.X.w;
            x.C((W) ((com.google.mlkit.vision.camera.a) cVar.b).j.get());
            com.google.mlkit.vision.camera.a.l.g("bind to lifecycle");
            com.google.mlkit.vision.camera.a aVar6 = (com.google.mlkit.vision.camera.a) cVar.b;
            gVar.d(aVar6, aVar6.c, x, a);
            ((com.google.mlkit.vision.camera.a) cVar.b).d(1);
        } catch (Throwable th2) {
            Trace.endSection();
            throw th2;
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:19:0x0043, code lost:
    
        if (r1 == false) goto L51;
     */
    /* JADX WARN: Code restructure failed: missing block: B:24:0x004c, code lost:
    
        r1 = r1 | java.lang.Thread.interrupted();
        r2 = null;
     */
    /* JADX WARN: Code restructure failed: missing block: B:25:0x004e, code lost:
    
        ((java.lang.Runnable) r10.b).run();
     */
    /* JADX WARN: Code restructure failed: missing block: B:30:0x005a, code lost:
    
        r0 = move-exception;
     */
    /* JADX WARN: Code restructure failed: missing block: B:32:0x005c, code lost:
    
        r3 = move-exception;
     */
    /* JADX WARN: Code restructure failed: missing block: B:33:0x005d, code lost:
    
        com.google.firebase.concurrent.i.f.log(java.util.logging.Level.SEVERE, "Exception while executing runnable " + ((java.lang.Runnable) r10.b), (java.lang.Throwable) r3);
     */
    /* JADX WARN: Code restructure failed: missing block: B:35:0x007a, code lost:
    
        r10.b = null;
     */
    /* JADX WARN: Code restructure failed: missing block: B:36:0x007c, code lost:
    
        throw r0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:51:?, code lost:
    
        return;
     */
    /* JADX WARN: Removed duplicated region for block: B:47:0x003c A[SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void b() {
        /*
            r10 = this;
            r0 = 0
            r1 = r0
        L2:
            java.lang.Object r2 = r10.c     // Catch: java.lang.Throwable -> L58
            com.google.firebase.concurrent.i r2 = (com.google.firebase.concurrent.i) r2     // Catch: java.lang.Throwable -> L58
            java.util.ArrayDeque r2 = r2.b     // Catch: java.lang.Throwable -> L58
            monitor-enter(r2)     // Catch: java.lang.Throwable -> L58
            r3 = 1
            if (r0 != 0) goto L2c
            java.lang.Object r0 = r10.c     // Catch: java.lang.Throwable -> L20
            com.google.firebase.concurrent.i r0 = (com.google.firebase.concurrent.i) r0     // Catch: java.lang.Throwable -> L20
            int r4 = r0.c     // Catch: java.lang.Throwable -> L20
            r5 = 4
            if (r4 != r5) goto L22
            monitor-exit(r2)     // Catch: java.lang.Throwable -> L20
            if (r1 == 0) goto L46
        L18:
            java.lang.Thread r0 = java.lang.Thread.currentThread()
            r0.interrupt()
            goto L46
        L20:
            r0 = move-exception
            goto L7d
        L22:
            long r6 = r0.d     // Catch: java.lang.Throwable -> L20
            r8 = 1
            long r6 = r6 + r8
            r0.d = r6     // Catch: java.lang.Throwable -> L20
            r0.c = r5     // Catch: java.lang.Throwable -> L20
            r0 = r3
        L2c:
            java.lang.Object r4 = r10.c     // Catch: java.lang.Throwable -> L20
            com.google.firebase.concurrent.i r4 = (com.google.firebase.concurrent.i) r4     // Catch: java.lang.Throwable -> L20
            java.util.ArrayDeque r4 = r4.b     // Catch: java.lang.Throwable -> L20
            java.lang.Object r4 = r4.poll()     // Catch: java.lang.Throwable -> L20
            java.lang.Runnable r4 = (java.lang.Runnable) r4     // Catch: java.lang.Throwable -> L20
            r10.b = r4     // Catch: java.lang.Throwable -> L20
            if (r4 != 0) goto L47
            java.lang.Object r0 = r10.c     // Catch: java.lang.Throwable -> L20
            com.google.firebase.concurrent.i r0 = (com.google.firebase.concurrent.i) r0     // Catch: java.lang.Throwable -> L20
            r0.c = r3     // Catch: java.lang.Throwable -> L20
            monitor-exit(r2)     // Catch: java.lang.Throwable -> L20
            if (r1 == 0) goto L46
            goto L18
        L46:
            return
        L47:
            monitor-exit(r2)     // Catch: java.lang.Throwable -> L20
            boolean r2 = java.lang.Thread.interrupted()     // Catch: java.lang.Throwable -> L58
            r1 = r1 | r2
            r2 = 0
            java.lang.Object r3 = r10.b     // Catch: java.lang.Throwable -> L5a java.lang.RuntimeException -> L5c
            java.lang.Runnable r3 = (java.lang.Runnable) r3     // Catch: java.lang.Throwable -> L5a java.lang.RuntimeException -> L5c
            r3.run()     // Catch: java.lang.Throwable -> L5a java.lang.RuntimeException -> L5c
        L55:
            r10.b = r2     // Catch: java.lang.Throwable -> L58
            goto L2
        L58:
            r0 = move-exception
            goto L7f
        L5a:
            r0 = move-exception
            goto L7a
        L5c:
            r3 = move-exception
            java.util.logging.Logger r4 = com.google.firebase.concurrent.i.f     // Catch: java.lang.Throwable -> L5a
            java.util.logging.Level r5 = java.util.logging.Level.SEVERE     // Catch: java.lang.Throwable -> L5a
            java.lang.StringBuilder r6 = new java.lang.StringBuilder     // Catch: java.lang.Throwable -> L5a
            r6.<init>()     // Catch: java.lang.Throwable -> L5a
            java.lang.String r7 = "Exception while executing runnable "
            r6.append(r7)     // Catch: java.lang.Throwable -> L5a
            java.lang.Object r7 = r10.b     // Catch: java.lang.Throwable -> L5a
            java.lang.Runnable r7 = (java.lang.Runnable) r7     // Catch: java.lang.Throwable -> L5a
            r6.append(r7)     // Catch: java.lang.Throwable -> L5a
            java.lang.String r6 = r6.toString()     // Catch: java.lang.Throwable -> L5a
            r4.log(r5, r6, r3)     // Catch: java.lang.Throwable -> L5a
            goto L55
        L7a:
            r10.b = r2     // Catch: java.lang.Throwable -> L58
            throw r0     // Catch: java.lang.Throwable -> L58
        L7d:
            monitor-exit(r2)     // Catch: java.lang.Throwable -> L20
            throw r0     // Catch: java.lang.Throwable -> L58
        L7f:
            if (r1 == 0) goto L88
            java.lang.Thread r1 = java.lang.Thread.currentThread()
            r1.interrupt()
        L88:
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.tasks.k.b():void");
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                j jVar = (j) this.c;
                synchronized (jVar.c) {
                    try {
                        c cVar = (c) jVar.d;
                        if (cVar != null) {
                            Exception excG = ((Task) this.b).g();
                            u.h(excG);
                            cVar.t(excG);
                        }
                    } finally {
                    }
                }
                return;
            case 1:
                j jVar2 = (j) this.c;
                try {
                    Task taskG = ((e) jVar2.c).g(((Task) this.b).h());
                    if (taskG == null) {
                        jVar2.t(new NullPointerException("Continuation returned null"));
                        return;
                    }
                    androidx.camera.core.impl.utils.executor.a aVar = g.b;
                    taskG.d(aVar, jVar2);
                    taskG.c(aVar, jVar2);
                    taskG.a(aVar, jVar2);
                    return;
                } catch (RuntimeExecutionException e) {
                    if (e.getCause() instanceof Exception) {
                        jVar2.t((Exception) e.getCause());
                        return;
                    } else {
                        jVar2.t(e);
                        return;
                    }
                } catch (CancellationException unused) {
                    jVar2.j();
                    return;
                } catch (Exception e2) {
                    jVar2.t(e2);
                    return;
                }
            case 2:
                try {
                    b();
                    return;
                } catch (Error e3) {
                    synchronized (((com.google.firebase.concurrent.i) this.c).b) {
                        ((com.google.firebase.concurrent.i) this.c).c = 1;
                        throw e3;
                    }
                }
            case 3:
                Callable callable = (Callable) this.b;
                f fVar = (f) this.c;
                try {
                    fVar.b(callable.call());
                    return;
                } catch (MlKitException e4) {
                    fVar.a(e4);
                    return;
                } catch (Exception e5) {
                    fVar.a(new MlKitException("Internal error has occurred when executing ML Kit tasks", e5));
                    return;
                }
            case 4:
                androidx.browser.customtabs.k kVar = (androidx.browser.customtabs.k) this.b;
                u.k(((Thread) ((AtomicReference) kVar.d).getAndSet(Thread.currentThread())) == null);
                try {
                    ((Runnable) this.c).run();
                    ((AtomicReference) kVar.d).set(null);
                    kVar.o();
                    return;
                } catch (Throwable th) {
                    try {
                        ((AtomicReference) kVar.d).set(null);
                        kVar.o();
                    } catch (Throwable th2) {
                        th.addSuppressed(th2);
                    }
                    throw th;
                }
            case 5:
                a();
                return;
            case 6:
                ((io.reactivex.rxjava3.core.g) this.c).e((io.reactivex.rxjava3.internal.observers.e) this.b);
                return;
            case 7:
                io.reactivex.rxjava3.internal.schedulers.f fVar2 = (io.reactivex.rxjava3.internal.schedulers.f) this.b;
                io.reactivex.rxjava3.disposables.d dVar = fVar2.b;
                io.reactivex.rxjava3.disposables.b bVarB = ((io.reactivex.rxjava3.android.schedulers.e) this.c).b(fVar2);
                dVar.getClass();
                io.reactivex.rxjava3.internal.disposables.a.c(dVar, bVarB);
                return;
            default:
                int i = 0;
                while (true) {
                    try {
                        ((Runnable) this.b).run();
                    } catch (Throwable th3) {
                        E.u(kotlin.coroutines.n.a, th3);
                    }
                    Runnable runnableK0 = ((kotlinx.coroutines.internal.g) this.c).k0();
                    if (runnableK0 == null) {
                        return;
                    }
                    try {
                        this.b = runnableK0;
                        i++;
                        if (i >= 16) {
                            kotlinx.coroutines.internal.g gVar = (kotlinx.coroutines.internal.g) this.c;
                            if (kotlinx.coroutines.internal.b.i(gVar.c, gVar)) {
                                kotlinx.coroutines.internal.g gVar2 = (kotlinx.coroutines.internal.g) this.c;
                                kotlinx.coroutines.internal.b.h(gVar2.c, gVar2, this);
                                return;
                            }
                        }
                    } catch (Throwable th4) {
                        kotlinx.coroutines.internal.g gVar3 = (kotlinx.coroutines.internal.g) this.c;
                        synchronized (gVar3.f) {
                            kotlinx.coroutines.internal.g.g.decrementAndGet(gVar3);
                            throw th4;
                        }
                    }
                }
        }
    }

    public String toString() {
        switch (this.a) {
            case 2:
                Runnable runnable = (Runnable) this.b;
                if (runnable != null) {
                    return "SequentialExecutorWorker{running=" + runnable + "}";
                }
                StringBuilder sb = new StringBuilder("SequentialExecutorWorker{state=");
                int i = ((com.google.firebase.concurrent.i) this.c).c;
                sb.append(i != 1 ? i != 2 ? i != 3 ? i != 4 ? "null" : "RUNNING" : "QUEUED" : "QUEUING" : "IDLE");
                sb.append("}");
                return sb.toString();
            default:
                return super.toString();
        }
    }

    public /* synthetic */ k(Object obj, boolean z, Object obj2, int i) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
    }

    public k(com.google.firebase.concurrent.i iVar) {
        this.a = 2;
        this.c = iVar;
    }
}

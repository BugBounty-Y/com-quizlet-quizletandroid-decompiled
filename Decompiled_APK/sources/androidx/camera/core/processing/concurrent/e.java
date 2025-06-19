package androidx.camera.core.processing.concurrent;

import android.graphics.SurfaceTexture;
import android.os.Handler;
import android.os.HandlerThread;
import android.view.Surface;
import androidx.activity.RunnableC0041m;
import androidx.activity.r;
import androidx.camera.camera2.internal.C0143u;
import androidx.camera.camera2.internal.RunnableC0130g;
import androidx.camera.camera2.internal.RunnableC0131h;
import androidx.camera.core.C0196t;
import androidx.camera.core.Q;
import androidx.camera.core.e0;
import androidx.camera.core.j0;
import androidx.camera.core.processing.l;
import androidx.camera.core.processing.m;
import androidx.camera.core.processing.util.i;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.google.android.gms.internal.mlkit_vision_barcode.Y5;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.atomic.AtomicBoolean;

/* loaded from: classes.dex */
public final class e implements m, SurfaceTexture.OnFrameAvailableListener {
    public final c a;
    public final HandlerThread b;
    public final androidx.camera.core.impl.utils.executor.e c;
    public final Handler d;
    public int e;
    public boolean f;
    public final AtomicBoolean g;
    public final LinkedHashMap h;
    public SurfaceTexture i;
    public SurfaceTexture j;

    public e(C0196t c0196t, Q q, Q q2) {
        Map map = Collections.EMPTY_MAP;
        this.e = 0;
        this.f = false;
        this.g = new AtomicBoolean(false);
        this.h = new LinkedHashMap();
        HandlerThread handlerThread = new HandlerThread("GL Thread");
        this.b = handlerThread;
        handlerThread.start();
        Handler handler = new Handler(handlerThread.getLooper());
        this.d = handler;
        this.c = new androidx.camera.core.impl.utils.executor.e(handler);
        this.a = new c(q, q2);
        try {
            try {
                Y5.b(new C0143u(this, c0196t)).get();
            } catch (InterruptedException | ExecutionException e) {
                e = e;
                e = e instanceof ExecutionException ? e.getCause() : e;
                if (!(e instanceof RuntimeException)) {
                    throw new IllegalStateException("Failed to create DefaultSurfaceProcessor", e);
                }
                throw ((RuntimeException) e);
            }
        } catch (RuntimeException e2) {
            a();
            throw e2;
        }
    }

    @Override // androidx.camera.core.processing.m
    public final void a() {
        if (this.g.getAndSet(true)) {
            return;
        }
        e(new RunnableC0041m(this, 23), new RunnableC0131h(0));
    }

    @Override // androidx.camera.core.processing.m
    public final void b(l lVar) {
        if (this.g.get()) {
            lVar.close();
            return;
        }
        r rVar = new r(20, this, lVar);
        Objects.requireNonNull(lVar);
        e(rVar, new RunnableC0041m(lVar, 18));
    }

    @Override // androidx.camera.core.processing.m
    public final void c(j0 j0Var) {
        if (this.g.get()) {
            j0Var.c();
        } else {
            e(new r(19, this, j0Var), new e0(j0Var, 1));
        }
    }

    public final void d() {
        if (this.f && this.e == 0) {
            LinkedHashMap linkedHashMap = this.h;
            Iterator it2 = linkedHashMap.keySet().iterator();
            while (it2.hasNext()) {
                ((l) it2.next()).close();
            }
            linkedHashMap.clear();
            c cVar = this.a;
            if (((AtomicBoolean) cVar.c).getAndSet(false)) {
                i.c((Thread) cVar.e);
                cVar.p();
            }
            cVar.n = -1;
            cVar.o = -1;
            this.b.quit();
        }
    }

    public final void e(Runnable runnable, Runnable runnable2) {
        try {
            this.c.execute(new RunnableC0130g(this, runnable2, runnable, 8));
        } catch (RejectedExecutionException e) {
            AbstractC3053s1.i("DualSurfaceProcessor", "Unable to executor runnable", e);
            runnable2.run();
        }
    }

    @Override // android.graphics.SurfaceTexture.OnFrameAvailableListener
    public final void onFrameAvailable(SurfaceTexture surfaceTexture) {
        SurfaceTexture surfaceTexture2;
        if (this.g.get() || (surfaceTexture2 = this.i) == null || this.j == null) {
            return;
        }
        surfaceTexture2.updateTexImage();
        this.j.updateTexImage();
        for (Map.Entry entry : this.h.entrySet()) {
            Surface surface = (Surface) entry.getValue();
            l lVar = (l) entry.getKey();
            if (lVar.c == 34) {
                try {
                    this.a.x(surfaceTexture.getTimestamp(), surface, lVar, this.i, this.j);
                } catch (RuntimeException e) {
                    AbstractC3053s1.d("DualSurfaceProcessor", "Failed to render with OpenGL.", e);
                }
            }
        }
    }
}

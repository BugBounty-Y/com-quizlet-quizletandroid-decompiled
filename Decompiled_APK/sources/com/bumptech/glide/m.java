package com.bumptech.glide;

import android.content.ComponentCallbacks2;
import android.content.Context;
import android.content.res.Configuration;
import android.graphics.Bitmap;
import android.os.Looper;
import android.util.Log;
import androidx.appcompat.app.J;
import com.bumptech.glide.manager.q;
import com.google.android.gms.internal.measurement.C3083y1;
import com.google.android.gms.internal.mlkit_common.u;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;

/* loaded from: classes.dex */
public final class m implements ComponentCallbacks2, com.bumptech.glide.manager.i {
    public static final com.bumptech.glide.request.f k;
    public final Glide a;
    public final Context b;
    public final com.bumptech.glide.manager.g c;
    public final C3083y1 d;
    public final com.bumptech.glide.manager.m e;
    public final q f;
    public final J g;
    public final com.bumptech.glide.manager.b h;
    public final CopyOnWriteArrayList i;
    public final com.bumptech.glide.request.f j;

    static {
        com.bumptech.glide.request.f fVar = (com.bumptech.glide.request.f) new com.bumptech.glide.request.f().d(Bitmap.class);
        fVar.m = true;
        k = fVar;
        ((com.bumptech.glide.request.f) new com.bumptech.glide.request.f().d(com.bumptech.glide.load.resource.gif.b.class)).m = true;
    }

    public m(Glide glide, com.bumptech.glide.manager.g gVar, com.bumptech.glide.manager.m mVar, Context context) {
        com.bumptech.glide.request.f fVar;
        C3083y1 c3083y1 = new C3083y1(4);
        u uVar = glide.f;
        this.f = new q();
        J j = new J(this, 15);
        this.g = j;
        this.a = glide;
        this.c = gVar;
        this.e = mVar;
        this.d = c3083y1;
        this.b = context;
        Context applicationContext = context.getApplicationContext();
        l lVar = new l(this, c3083y1);
        uVar.getClass();
        boolean z = androidx.core.content.c.a(applicationContext, "android.permission.ACCESS_NETWORK_STATE") == 0;
        Log.isLoggable("ConnectivityMonitor", 3);
        com.bumptech.glide.manager.b cVar = z ? new com.bumptech.glide.manager.c(applicationContext, lVar) : new com.bumptech.glide.manager.k();
        this.h = cVar;
        synchronized (glide.g) {
            if (glide.g.contains(this)) {
                throw new IllegalStateException("Cannot register already registered manager");
            }
            glide.g.add(this);
        }
        char[] cArr = com.bumptech.glide.util.m.a;
        if (Looper.myLooper() == Looper.getMainLooper()) {
            gVar.a(this);
        } else {
            com.bumptech.glide.util.m.f().post(j);
        }
        gVar.a(cVar);
        this.i = new CopyOnWriteArrayList(glide.c.e);
        e eVar = glide.c;
        synchronized (eVar) {
            try {
                if (eVar.j == null) {
                    eVar.d.getClass();
                    com.bumptech.glide.request.f fVar2 = new com.bumptech.glide.request.f();
                    fVar2.m = true;
                    eVar.j = fVar2;
                }
                fVar = eVar.j;
            } finally {
            }
        }
        synchronized (this) {
            com.bumptech.glide.request.f fVar3 = (com.bumptech.glide.request.f) fVar.clone();
            if (fVar3.m && !fVar3.n) {
                throw new IllegalStateException("You cannot auto lock an already locked options object, try clone() first");
            }
            fVar3.n = true;
            fVar3.m = true;
            this.j = fVar3;
        }
    }

    public final void i(com.bumptech.glide.request.target.e eVar) {
        if (eVar == null) {
            return;
        }
        boolean zM = m(eVar);
        com.bumptech.glide.request.c cVarB = eVar.b();
        if (zM) {
            return;
        }
        Glide glide = this.a;
        synchronized (glide.g) {
            try {
                Iterator it2 = glide.g.iterator();
                while (it2.hasNext()) {
                    if (((m) it2.next()).m(eVar)) {
                        return;
                    }
                }
                if (cVarB != null) {
                    eVar.d(null);
                    cVarB.clear();
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public final synchronized void j() {
        try {
            Iterator it2 = com.bumptech.glide.util.m.e(this.f.a).iterator();
            while (it2.hasNext()) {
                i((com.bumptech.glide.request.target.e) it2.next());
            }
            this.f.a.clear();
        } catch (Throwable th) {
            throw th;
        }
    }

    public final synchronized void k() {
        C3083y1 c3083y1 = this.d;
        c3083y1.b = true;
        Iterator it2 = com.bumptech.glide.util.m.e((Set) c3083y1.c).iterator();
        while (it2.hasNext()) {
            com.bumptech.glide.request.c cVar = (com.bumptech.glide.request.c) it2.next();
            if (cVar.isRunning()) {
                cVar.pause();
                ((HashSet) c3083y1.d).add(cVar);
            }
        }
    }

    public final synchronized void l() {
        C3083y1 c3083y1 = this.d;
        c3083y1.b = false;
        Iterator it2 = com.bumptech.glide.util.m.e((Set) c3083y1.c).iterator();
        while (it2.hasNext()) {
            com.bumptech.glide.request.c cVar = (com.bumptech.glide.request.c) it2.next();
            if (!cVar.i() && !cVar.isRunning()) {
                cVar.g();
            }
        }
        ((HashSet) c3083y1.d).clear();
    }

    public final synchronized boolean m(com.bumptech.glide.request.target.e eVar) {
        com.bumptech.glide.request.c cVarB = eVar.b();
        if (cVarB == null) {
            return true;
        }
        if (!this.d.f(cVarB)) {
            return false;
        }
        this.f.a.remove(eVar);
        eVar.d(null);
        return true;
    }

    @Override // android.content.ComponentCallbacks
    public final void onConfigurationChanged(Configuration configuration) {
    }

    @Override // com.bumptech.glide.manager.i
    public final synchronized void onDestroy() {
        this.f.onDestroy();
        j();
        C3083y1 c3083y1 = this.d;
        Iterator it2 = com.bumptech.glide.util.m.e((Set) c3083y1.c).iterator();
        while (it2.hasNext()) {
            c3083y1.f((com.bumptech.glide.request.c) it2.next());
        }
        ((HashSet) c3083y1.d).clear();
        this.c.c(this);
        this.c.c(this.h);
        com.bumptech.glide.util.m.f().removeCallbacks(this.g);
        Glide glide = this.a;
        synchronized (glide.g) {
            if (!glide.g.contains(this)) {
                throw new IllegalStateException("Cannot unregister not yet registered manager");
            }
            glide.g.remove(this);
        }
    }

    @Override // android.content.ComponentCallbacks
    public final void onLowMemory() {
    }

    @Override // com.bumptech.glide.manager.i
    public final synchronized void onStart() {
        l();
        this.f.onStart();
    }

    @Override // com.bumptech.glide.manager.i
    public final synchronized void onStop() {
        this.f.onStop();
        k();
    }

    @Override // android.content.ComponentCallbacks2
    public final void onTrimMemory(int i) {
    }

    public final synchronized String toString() {
        return super.toString() + "{tracker=" + this.d + ", treeNode=" + this.e + "}";
    }
}

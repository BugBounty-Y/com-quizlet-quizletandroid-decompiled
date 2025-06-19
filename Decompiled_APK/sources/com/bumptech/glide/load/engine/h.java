package com.bumptech.glide.load.engine;

import android.os.SystemClock;
import android.util.Log;
import androidx.camera.camera2.internal.AbstractC0147y;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.Objects;

/* loaded from: classes.dex */
public final class h implements e, Runnable, Comparable, com.bumptech.glide.util.pool.b {
    public boolean A;
    public int B;
    public int C;
    public int D;
    public final k d;
    public final com.quizlet.data.repository.course.membership.c e;
    public com.bumptech.glide.e h;
    public com.bumptech.glide.load.e i;
    public com.bumptech.glide.g j;
    public p k;
    public int l;
    public int m;
    public j n;
    public com.bumptech.glide.load.h o;
    public o p;
    public int q;
    public Object r;
    public Thread s;
    public com.bumptech.glide.load.e t;
    public com.bumptech.glide.load.e u;
    public Object v;
    public com.bumptech.glide.load.data.e w;
    public volatile f x;
    public volatile boolean y;
    public volatile boolean z;
    public final g a = new g();
    public final ArrayList b = new ArrayList();
    public final com.bumptech.glide.util.pool.e c = new com.bumptech.glide.util.pool.e();
    public final com.quizlet.data.repository.set.f f = new com.quizlet.data.repository.set.f(4);
    public final androidx.camera.camera2.internal.compat.workaround.c g = new androidx.camera.camera2.internal.compat.workaround.c();

    public h(k kVar, com.quizlet.data.repository.course.membership.c cVar) {
        this.d = kVar;
        this.e = cVar;
    }

    @Override // com.bumptech.glide.load.engine.e
    public final void a(com.bumptech.glide.load.e eVar, Object obj, com.bumptech.glide.load.data.e eVar2, int i, com.bumptech.glide.load.e eVar3) {
        this.t = eVar;
        this.v = obj;
        this.w = eVar2;
        this.D = i;
        this.u = eVar3;
        this.A = eVar != this.a.a().get(0);
        if (Thread.currentThread() != this.s) {
            k(3);
        } else {
            f();
        }
    }

    @Override // com.bumptech.glide.util.pool.b
    public final com.bumptech.glide.util.pool.e b() {
        return this.c;
    }

    @Override // com.bumptech.glide.load.engine.e
    public final void c(com.bumptech.glide.load.e eVar, Exception exc, com.bumptech.glide.load.data.e eVar2, int i) {
        eVar2.f();
        GlideException glideException = new GlideException("Fetching data failed", Collections.singletonList(exc));
        Class dataClass = eVar2.getDataClass();
        glideException.b = eVar;
        glideException.c = i;
        glideException.d = dataClass;
        this.b.add(glideException);
        if (Thread.currentThread() != this.s) {
            k(2);
        } else {
            l();
        }
    }

    @Override // java.lang.Comparable
    public final int compareTo(Object obj) {
        h hVar = (h) obj;
        int iOrdinal = this.j.ordinal() - hVar.j.ordinal();
        return iOrdinal == 0 ? this.q - hVar.q : iOrdinal;
    }

    public final v d(com.bumptech.glide.load.data.e eVar, Object obj, int i) {
        if (obj == null) {
            eVar.f();
            return null;
        }
        try {
            int i2 = com.bumptech.glide.util.h.a;
            SystemClock.elapsedRealtimeNanos();
            v vVarE = e(i, obj);
            if (Log.isLoggable("DecodeJob", 2)) {
                vVarE.toString();
                SystemClock.elapsedRealtimeNanos();
                Objects.toString(this.k);
                Thread.currentThread().getName();
            }
            return vVarE;
        } finally {
            eVar.f();
        }
    }

    public final v e(int i, Object obj) {
        Class<?> cls = obj.getClass();
        g gVar = this.a;
        t tVarC = gVar.c(cls);
        com.bumptech.glide.load.h hVar = this.o;
        boolean z = i == 4 || gVar.r;
        com.bumptech.glide.load.g gVar2 = com.bumptech.glide.load.resource.bitmap.o.i;
        Boolean bool = (Boolean) hVar.c(gVar2);
        if (bool == null || (bool.booleanValue() && !z)) {
            hVar = new com.bumptech.glide.load.h();
            com.bumptech.glide.load.h hVar2 = this.o;
            com.bumptech.glide.util.c cVar = hVar.b;
            cVar.h(hVar2.b);
            cVar.put(gVar2, Boolean.valueOf(z));
        }
        com.bumptech.glide.load.h hVar3 = hVar;
        com.bumptech.glide.load.data.g gVarG = this.h.a().g(obj);
        try {
            return tVarC.a(this.l, this.m, new com.android.billingclient.api.s(this, i, 9), hVar3, gVarG);
        } finally {
            gVarG.f();
        }
    }

    public final void f() {
        v vVarD;
        boolean zA;
        if (Log.isLoggable("DecodeJob", 2)) {
            String str = "data: " + this.v + ", cache key: " + this.t + ", fetcher: " + this.w;
            int i = com.bumptech.glide.util.h.a;
            SystemClock.elapsedRealtimeNanos();
            Objects.toString(this.k);
            if (str != null) {
                ", ".concat(str);
            }
            Thread.currentThread().getName();
        }
        u uVar = null;
        try {
            vVarD = d(this.w, this.v, this.D);
        } catch (GlideException e) {
            com.bumptech.glide.load.e eVar = this.u;
            int i2 = this.D;
            e.b = eVar;
            e.c = i2;
            e.d = null;
            this.b.add(e);
            vVarD = null;
        }
        if (vVarD == null) {
            l();
            return;
        }
        int i3 = this.D;
        boolean z = this.A;
        if (vVarD instanceof s) {
            ((s) vVarD).b();
        }
        if (((u) this.f.d) != null) {
            uVar = (u) u.e.a();
            uVar.d = false;
            uVar.c = true;
            uVar.b = vVarD;
            vVarD = uVar;
        }
        n();
        o oVar = this.p;
        synchronized (oVar) {
            oVar.n = vVarD;
            oVar.o = i3;
            oVar.v = z;
        }
        synchronized (oVar) {
            try {
                oVar.b.a();
                if (oVar.u) {
                    oVar.n.recycle();
                    oVar.g();
                } else {
                    if (((ArrayList) oVar.a.b).isEmpty()) {
                        throw new IllegalStateException("Received a resource without any callbacks to notify");
                    }
                    if (oVar.p) {
                        throw new IllegalStateException("Already have resource");
                    }
                    com.google.android.material.shape.e eVar2 = oVar.e;
                    v vVar = oVar.n;
                    boolean z2 = oVar.l;
                    p pVar = oVar.k;
                    l lVar = oVar.c;
                    eVar2.getClass();
                    oVar.s = new q(vVar, z2, true, pVar, lVar);
                    oVar.p = true;
                    n nVar = oVar.a;
                    nVar.getClass();
                    ArrayList arrayList = new ArrayList((ArrayList) nVar.b);
                    oVar.e(arrayList.size() + 1);
                    oVar.f.c(oVar, oVar.k, oVar.s);
                    Iterator it2 = arrayList.iterator();
                    while (it2.hasNext()) {
                        m mVar = (m) it2.next();
                        mVar.b.execute(new com.google.common.util.concurrent.d(oVar, z, mVar.a, 11));
                    }
                    oVar.d();
                }
            } finally {
            }
        }
        this.B = 5;
        try {
            com.quizlet.data.repository.set.f fVar = this.f;
            if (((u) fVar.d) != null) {
                k kVar = this.d;
                com.bumptech.glide.load.h hVar = this.o;
                fVar.getClass();
                try {
                    kVar.a().d((com.bumptech.glide.load.e) fVar.b, new com.quizlet.data.repository.login.a((com.bumptech.glide.load.k) fVar.c, (u) fVar.d, hVar));
                    ((u) fVar.d).d();
                } catch (Throwable th) {
                    ((u) fVar.d).d();
                    throw th;
                }
            }
            androidx.camera.camera2.internal.compat.workaround.c cVar = this.g;
            synchronized (cVar) {
                cVar.b = true;
                zA = cVar.a();
            }
            if (zA) {
                j();
            }
        } finally {
            if (uVar != null) {
                uVar.d();
            }
        }
    }

    public final f g() {
        int iK = AbstractC0147y.k(this.B);
        g gVar = this.a;
        if (iK == 1) {
            return new w(gVar, this);
        }
        if (iK == 2) {
            return new c(gVar.a(), gVar, this);
        }
        if (iK == 3) {
            return new z(gVar, this);
        }
        if (iK == 5) {
            return null;
        }
        throw new IllegalStateException("Unrecognized stage: ".concat(assistantMode.refactored.a.s(this.B)));
    }

    public final int h(int i) {
        boolean z;
        boolean z2;
        int iK = AbstractC0147y.k(i);
        if (iK == 0) {
            switch (this.n.a) {
                case 0:
                case 1:
                    z = false;
                    break;
                default:
                    z = true;
                    break;
            }
            if (z) {
                return 2;
            }
            return h(2);
        }
        if (iK != 1) {
            if (iK == 2) {
                return 4;
            }
            if (iK == 3 || iK == 5) {
                return 6;
            }
            throw new IllegalArgumentException("Unrecognized stage: ".concat(assistantMode.refactored.a.s(i)));
        }
        switch (this.n.a) {
            case 0:
                z2 = false;
                break;
            case 1:
            default:
                z2 = true;
                break;
        }
        if (z2) {
            return 3;
        }
        return h(3);
    }

    public final void i() {
        boolean zA;
        n();
        GlideException glideException = new GlideException("Failed to load resource", new ArrayList(this.b));
        o oVar = this.p;
        synchronized (oVar) {
            oVar.q = glideException;
        }
        synchronized (oVar) {
            try {
                oVar.b.a();
                if (oVar.u) {
                    oVar.g();
                } else {
                    if (((ArrayList) oVar.a.b).isEmpty()) {
                        throw new IllegalStateException("Received an exception without any callbacks to notify");
                    }
                    if (oVar.r) {
                        throw new IllegalStateException("Already failed once");
                    }
                    oVar.r = true;
                    p pVar = oVar.k;
                    n nVar = oVar.a;
                    nVar.getClass();
                    ArrayList arrayList = new ArrayList((ArrayList) nVar.b);
                    oVar.e(arrayList.size() + 1);
                    oVar.f.c(oVar, pVar, null);
                    Iterator it2 = arrayList.iterator();
                    while (it2.hasNext()) {
                        m mVar = (m) it2.next();
                        mVar.b.execute(new androidx.camera.core.impl.utils.futures.h(oVar, false, mVar.a, 11));
                    }
                    oVar.d();
                }
            } finally {
            }
        }
        androidx.camera.camera2.internal.compat.workaround.c cVar = this.g;
        synchronized (cVar) {
            cVar.c = true;
            zA = cVar.a();
        }
        if (zA) {
            j();
        }
    }

    public final void j() {
        androidx.camera.camera2.internal.compat.workaround.c cVar = this.g;
        synchronized (cVar) {
            cVar.b = false;
            cVar.a = false;
            cVar.c = false;
        }
        com.quizlet.data.repository.set.f fVar = this.f;
        fVar.b = null;
        fVar.c = null;
        fVar.d = null;
        g gVar = this.a;
        gVar.c = null;
        gVar.d = null;
        gVar.n = null;
        gVar.g = null;
        gVar.k = null;
        gVar.i = null;
        gVar.o = null;
        gVar.j = null;
        gVar.p = null;
        gVar.a.clear();
        gVar.l = false;
        gVar.b.clear();
        gVar.m = false;
        this.y = false;
        this.h = null;
        this.i = null;
        this.o = null;
        this.j = null;
        this.k = null;
        this.p = null;
        this.B = 0;
        this.x = null;
        this.s = null;
        this.t = null;
        this.v = null;
        this.D = 0;
        this.w = null;
        this.z = false;
        this.r = null;
        this.b.clear();
        this.e.o(this);
    }

    public final void k(int i) {
        this.C = i;
        o oVar = this.p;
        (oVar.m ? oVar.i : oVar.h).execute(this);
    }

    public final void l() {
        this.s = Thread.currentThread();
        int i = com.bumptech.glide.util.h.a;
        SystemClock.elapsedRealtimeNanos();
        boolean zB = false;
        while (!this.z && this.x != null && !(zB = this.x.b())) {
            this.B = h(this.B);
            this.x = g();
            if (this.B == 4) {
                k(2);
                return;
            }
        }
        if ((this.B == 6 || this.z) && !zB) {
            i();
        }
    }

    public final void m() {
        int iK = AbstractC0147y.k(this.C);
        if (iK == 0) {
            this.B = h(1);
            this.x = g();
            l();
        } else if (iK == 1) {
            l();
        } else if (iK == 2) {
            f();
        } else {
            int i = this.C;
            throw new IllegalStateException("Unrecognized run reason: ".concat(i != 1 ? i != 2 ? i != 3 ? "null" : "DECODE_DATA" : "SWITCH_TO_SOURCE_SERVICE" : "INITIALIZE"));
        }
    }

    public final void n() {
        this.c.a();
        if (this.y) {
            throw new IllegalStateException("Already notified", this.b.isEmpty() ? null : (Throwable) android.support.v4.media.session.a.e(1, this.b));
        }
        this.y = true;
    }

    @Override // java.lang.Runnable
    public final void run() {
        com.bumptech.glide.load.data.e eVar = this.w;
        try {
            try {
                try {
                    if (this.z) {
                        i();
                        if (eVar != null) {
                            eVar.f();
                            return;
                        }
                        return;
                    }
                    m();
                    if (eVar != null) {
                        eVar.f();
                    }
                } catch (b e) {
                    throw e;
                }
            } catch (Throwable th) {
                Log.isLoggable("DecodeJob", 3);
                if (this.B != 5) {
                    this.b.add(th);
                    i();
                }
                if (!this.z) {
                    throw th;
                }
                throw th;
            }
        } catch (Throwable th2) {
            if (eVar != null) {
                eVar.f();
            }
            throw th2;
        }
    }
}

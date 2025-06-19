package com.bumptech.glide.load.engine;

import android.os.SystemClock;
import android.util.Log;
import androidx.appcompat.app.K;
import androidx.appcompat.widget.C0122z;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Objects;

/* loaded from: classes.dex */
public final class l {
    public static final boolean h = Log.isLoggable("Engine", 2);
    public final com.airbnb.lottie.network.c a;
    public final com.google.firebase.heartbeatinfo.e b;
    public final com.bumptech.glide.load.engine.cache.d c;
    public final com.onetrust.otpublishers.headless.UI.TVUI.datautils.d d;
    public final K e;
    public final C0122z f;
    public final com.quizlet.data.interactor.progress.c g;

    public l(com.bumptech.glide.load.engine.cache.d dVar, com.bumptech.glide.load.engine.cache.c cVar, com.bumptech.glide.load.engine.executor.e eVar, com.bumptech.glide.load.engine.executor.e eVar2, com.bumptech.glide.load.engine.executor.e eVar3, com.bumptech.glide.load.engine.executor.e eVar4) {
        this.c = dVar;
        k kVar = new k(cVar);
        com.quizlet.data.interactor.progress.c cVar2 = new com.quizlet.data.interactor.progress.c();
        this.g = cVar2;
        synchronized (this) {
            synchronized (cVar2) {
                cVar2.d = this;
            }
        }
        this.b = new com.google.firebase.heartbeatinfo.e(6);
        this.a = new com.airbnb.lottie.network.c(15);
        com.onetrust.otpublishers.headless.UI.TVUI.datautils.d dVar2 = new com.onetrust.otpublishers.headless.UI.TVUI.datautils.d();
        dVar2.g = com.bumptech.glide.util.pool.d.a(150, new androidx.webkit.internal.p(dVar2, 12));
        dVar2.a = eVar;
        dVar2.b = eVar2;
        dVar2.c = eVar3;
        dVar2.d = eVar4;
        dVar2.e = this;
        dVar2.f = this;
        this.d = dVar2;
        this.f = new C0122z(kVar);
        this.e = new K(7);
        dVar.e = this;
    }

    public static void e(v vVar) {
        if (!(vVar instanceof q)) {
            throw new IllegalArgumentException("Cannot release anything but an EngineResource");
        }
        ((q) vVar).d();
    }

    public final com.quizlet.data.repository.user.a a(com.bumptech.glide.e eVar, Object obj, com.bumptech.glide.load.e eVar2, int i, int i2, Class cls, Class cls2, com.bumptech.glide.g gVar, j jVar, com.bumptech.glide.util.c cVar, boolean z, boolean z2, com.bumptech.glide.load.h hVar, boolean z3, boolean z4, com.bumptech.glide.request.g gVar2, androidx.camera.core.impl.utils.executor.a aVar) {
        long jElapsedRealtimeNanos;
        if (h) {
            int i3 = com.bumptech.glide.util.h.a;
            jElapsedRealtimeNanos = SystemClock.elapsedRealtimeNanos();
        } else {
            jElapsedRealtimeNanos = 0;
        }
        this.b.getClass();
        p pVar = new p(obj, eVar2, i, i2, cVar, cls, cls2, hVar);
        synchronized (this) {
            try {
                q qVarB = b(pVar, z3, jElapsedRealtimeNanos);
                if (qVarB == null) {
                    return f(eVar, obj, eVar2, i, i2, cls, cls2, gVar, jVar, cVar, z, z2, hVar, z3, z4, gVar2, aVar, pVar, jElapsedRealtimeNanos);
                }
                gVar2.h(qVarB, 5, false);
                return null;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    /* JADX WARN: Finally extract failed */
    /* JADX WARN: Multi-variable type inference failed */
    public final q b(p pVar, boolean z, long j) throws Throwable {
        Throwable th;
        q qVar;
        Object obj;
        l lVar;
        p pVar2;
        q qVar2;
        if (z) {
            com.quizlet.data.interactor.progress.c cVar = this.g;
            synchronized (cVar) {
                try {
                    a aVar = (a) ((HashMap) cVar.b).get(pVar);
                    if (aVar == null) {
                        qVar = null;
                    } else {
                        qVar = (q) aVar.get();
                        if (qVar == null) {
                            try {
                                cVar.e(aVar);
                            } catch (Throwable th2) {
                                th = th2;
                                while (true) {
                                    try {
                                        throw th;
                                    } catch (Throwable th3) {
                                        th = th3;
                                    }
                                    th = th3;
                                }
                            }
                        }
                    }
                    if (qVar != null) {
                        qVar.b();
                    }
                    if (qVar != null) {
                        if (h) {
                            int i = com.bumptech.glide.util.h.a;
                            SystemClock.elapsedRealtimeNanos();
                            Objects.toString(pVar);
                        }
                        return qVar;
                    }
                    com.bumptech.glide.load.engine.cache.d dVar = this.c;
                    synchronized (dVar) {
                        try {
                            com.bumptech.glide.util.i iVar = (com.bumptech.glide.util.i) ((LinkedHashMap) dVar.d).remove(pVar);
                            if (iVar == null) {
                                obj = null;
                            } else {
                                dVar.c -= iVar.b;
                                obj = iVar.a;
                            }
                        } catch (Throwable th4) {
                            th = th4;
                            while (true) {
                                try {
                                    throw th;
                                } catch (Throwable th5) {
                                    th = th5;
                                }
                            }
                        }
                    }
                    v vVar = (v) obj;
                    if (vVar == null) {
                        lVar = this;
                        pVar2 = pVar;
                        qVar2 = null;
                    } else if (vVar instanceof q) {
                        qVar2 = (q) vVar;
                        lVar = this;
                        pVar2 = pVar;
                    } else {
                        lVar = this;
                        pVar2 = pVar;
                        qVar2 = new q(vVar, true, true, pVar2, lVar);
                    }
                    if (qVar2 != null) {
                        qVar2.b();
                        lVar.g.d(pVar2, qVar2);
                    }
                    if (qVar2 != null) {
                        if (h) {
                            int i2 = com.bumptech.glide.util.h.a;
                            SystemClock.elapsedRealtimeNanos();
                            Objects.toString(pVar2);
                        }
                        return qVar2;
                    }
                } catch (Throwable th6) {
                    th = th6;
                }
            }
        }
        return null;
    }

    public final synchronized void c(o oVar, p pVar, q qVar) {
        if (qVar != null) {
            try {
                if (qVar.a) {
                    this.g.d(pVar, qVar);
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        com.airbnb.lottie.network.c cVar = this.a;
        cVar.getClass();
        oVar.getClass();
        HashMap map = (HashMap) cVar.b;
        if (oVar.equals(map.get(pVar))) {
            map.remove(pVar);
        }
    }

    public final void d(p pVar, q qVar) {
        com.quizlet.data.interactor.progress.c cVar = this.g;
        synchronized (cVar) {
            a aVar = (a) ((HashMap) cVar.b).remove(pVar);
            if (aVar != null) {
                aVar.c = null;
                aVar.clear();
            }
        }
        if (qVar.a) {
        } else {
            this.e.F(qVar, false);
        }
    }

    public final com.quizlet.data.repository.user.a f(com.bumptech.glide.e eVar, Object obj, com.bumptech.glide.load.e eVar2, int i, int i2, Class cls, Class cls2, com.bumptech.glide.g gVar, j jVar, com.bumptech.glide.util.c cVar, boolean z, boolean z2, com.bumptech.glide.load.h hVar, boolean z3, boolean z4, com.bumptech.glide.request.g gVar2, androidx.camera.core.impl.utils.executor.a aVar, p pVar, long j) {
        o oVar = (o) ((HashMap) this.a.b).get(pVar);
        if (oVar != null) {
            oVar.a(gVar2, aVar);
            if (h) {
                int i3 = com.bumptech.glide.util.h.a;
                SystemClock.elapsedRealtimeNanos();
                Objects.toString(pVar);
            }
            return new com.quizlet.data.repository.user.a(this, gVar2, oVar);
        }
        o oVar2 = (o) ((com.quizlet.data.repository.course.membership.c) this.d.g).a();
        synchronized (oVar2) {
            oVar2.k = pVar;
            oVar2.l = z3;
            oVar2.m = z4;
        }
        C0122z c0122z = this.f;
        h hVar2 = (h) ((com.quizlet.data.repository.course.membership.c) c0122z.d).a();
        int i4 = c0122z.b;
        c0122z.b = i4 + 1;
        g gVar3 = hVar2.a;
        gVar3.c = eVar;
        gVar3.d = obj;
        gVar3.n = eVar2;
        gVar3.e = i;
        gVar3.f = i2;
        gVar3.p = jVar;
        gVar3.g = cls;
        gVar3.h = hVar2.d;
        gVar3.k = cls2;
        gVar3.o = gVar;
        gVar3.i = hVar;
        gVar3.j = cVar;
        gVar3.q = z;
        gVar3.r = z2;
        hVar2.h = eVar;
        hVar2.i = eVar2;
        hVar2.j = gVar;
        hVar2.k = pVar;
        hVar2.l = i;
        hVar2.m = i2;
        hVar2.n = jVar;
        hVar2.o = hVar;
        hVar2.p = oVar2;
        hVar2.q = i4;
        hVar2.C = 1;
        hVar2.r = obj;
        com.airbnb.lottie.network.c cVar2 = this.a;
        cVar2.getClass();
        ((HashMap) cVar2.b).put(pVar, oVar2);
        oVar2.a(gVar2, aVar);
        synchronized (oVar2) {
            oVar2.t = hVar2;
            int iH = hVar2.h(1);
            ((iH == 2 || iH == 3) ? oVar2.g : oVar2.m ? oVar2.i : oVar2.h).execute(hVar2);
        }
        if (h) {
            int i5 = com.bumptech.glide.util.h.a;
            SystemClock.elapsedRealtimeNanos();
            Objects.toString(pVar);
        }
        return new com.quizlet.data.repository.user.a(this, gVar2, oVar2);
    }
}

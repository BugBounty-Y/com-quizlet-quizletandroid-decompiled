package androidx.work.impl;

import android.content.Context;
import android.content.Intent;
import android.os.PowerManager;
import androidx.camera.camera2.internal.RunnableC0130g;
import androidx.compose.ui.node.V;
import androidx.work.C1422c;
import androidx.work.impl.foreground.SystemForegroundService;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3394t2;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

/* renamed from: androidx.work.impl.e, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1433e {
    public static final String l = androidx.work.z.e("Processor");
    public final Context b;
    public final C1422c c;
    public final androidx.work.impl.utils.taskexecutor.c d;
    public final WorkDatabase e;
    public final HashMap g = new HashMap();
    public final HashMap f = new HashMap();
    public final HashSet i = new HashSet();
    public final ArrayList j = new ArrayList();
    public PowerManager.WakeLock a = null;
    public final Object k = new Object();
    public final HashMap h = new HashMap();

    public C1433e(Context context, C1422c c1422c, androidx.work.impl.utils.taskexecutor.c cVar, WorkDatabase workDatabase) {
        this.b = context;
        this.c = c1422c;
        this.d = cVar;
        this.e = workDatabase;
    }

    public static boolean d(F f, int i) {
        if (f == null) {
            androidx.work.z.c().getClass();
            return false;
        }
        f.n.z(new WorkerStoppedException(i));
        androidx.work.z.c().getClass();
        return true;
    }

    public final void a(InterfaceC1430b interfaceC1430b) {
        synchronized (this.k) {
            this.j.add(interfaceC1430b);
        }
    }

    public final F b(String str) {
        F f = (F) this.f.remove(str);
        boolean z = f != null;
        if (!z) {
            f = (F) this.g.remove(str);
        }
        this.h.remove(str);
        if (z) {
            synchronized (this.k) {
                try {
                    if (this.f.isEmpty()) {
                        Context context = this.b;
                        String str2 = androidx.work.impl.foreground.a.j;
                        Intent intent = new Intent(context, (Class<?>) SystemForegroundService.class);
                        intent.setAction("ACTION_STOP_FOREGROUND");
                        try {
                            this.b.startService(intent);
                        } catch (Throwable th) {
                            androidx.work.z.c().b(l, "Unable to stop foreground service", th);
                        }
                        PowerManager.WakeLock wakeLock = this.a;
                        if (wakeLock != null) {
                            wakeLock.release();
                            this.a = null;
                        }
                    }
                } finally {
                }
            }
        }
        return f;
    }

    public final F c(String str) {
        F f = (F) this.f.get(str);
        return f == null ? (F) this.g.get(str) : f;
    }

    public final boolean e(String str) {
        boolean z;
        synchronized (this.k) {
            z = c(str) != null;
        }
        return z;
    }

    public final void f(InterfaceC1430b interfaceC1430b) {
        synchronized (this.k) {
            this.j.remove(interfaceC1430b);
        }
    }

    public final void g(androidx.work.impl.model.j jVar) {
        androidx.work.impl.utils.taskexecutor.c cVar = this.d;
        cVar.d.execute(new androidx.credentials.playservices.controllers.c(6, this, jVar));
    }

    public final boolean h(j jVar, com.google.android.gms.internal.appset.e eVar) {
        Throwable th;
        androidx.work.impl.model.j jVar2 = jVar.a;
        String str = jVar2.a;
        ArrayList arrayList = new ArrayList();
        androidx.work.impl.model.q qVar = (androidx.work.impl.model.q) this.e.n(new CallableC1432d(this, arrayList, str, 0));
        if (qVar == null) {
            androidx.work.z.c().f(l, "Didn't find WorkSpec for id " + jVar2);
            g(jVar2);
            return false;
        }
        synchronized (this.k) {
            try {
                try {
                    try {
                        if (e(str)) {
                            Set set = (Set) this.h.get(str);
                            if (((j) set.iterator().next()).a.b == jVar2.b) {
                                set.add(jVar);
                                androidx.work.z zVarC = androidx.work.z.c();
                                jVar2.toString();
                                zVarC.getClass();
                            } else {
                                g(jVar2);
                            }
                            return false;
                        }
                        if (qVar.t != jVar2.b) {
                            g(jVar2);
                            return false;
                        }
                        V v = new V(this.b, this.c, this.d, this, this.e, qVar, arrayList);
                        if (eVar != null) {
                            v.i = eVar;
                        }
                        F f = new F(v);
                        androidx.concurrent.futures.l lVarI = AbstractC3394t2.i(f.e.b.plus(kotlinx.coroutines.E.d()), new C(f, null));
                        lVarI.b.a(new RunnableC0130g(this, lVarI, f, 16), this.d.d);
                        this.g.put(str, f);
                        HashSet hashSet = new HashSet();
                        hashSet.add(jVar);
                        this.h.put(str, hashSet);
                        androidx.work.z zVarC2 = androidx.work.z.c();
                        jVar2.toString();
                        zVarC2.getClass();
                        return true;
                    } catch (Throwable th2) {
                        th = th2;
                        throw th;
                    }
                } catch (Throwable th3) {
                    th = th3;
                    th = th;
                    throw th;
                }
            } catch (Throwable th4) {
                th = th4;
                th = th;
                throw th;
            }
        }
    }
}

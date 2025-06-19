package androidx.work.impl.background.greedy;

import android.content.Context;
import android.text.TextUtils;
import androidx.camera.camera2.internal.RunnableC0130g;
import androidx.camera.camera2.internal.compat.h;
import androidx.camera.core.impl.y0;
import androidx.compose.foundation.text.input.internal.u;
import androidx.work.C1422c;
import androidx.work.C1425f;
import androidx.work.N;
import androidx.work.impl.C1433e;
import androidx.work.impl.InterfaceC1430b;
import androidx.work.impl.InterfaceC1435g;
import androidx.work.impl.constraints.j;
import androidx.work.impl.constraints.m;
import androidx.work.impl.constraints.o;
import androidx.work.impl.model.q;
import androidx.work.impl.utils.i;
import androidx.work.z;
import com.google.android.gms.internal.mlkit_vision_camera.A2;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.InterfaceC5025j0;

/* loaded from: classes.dex */
public final class c implements InterfaceC1435g, j, InterfaceC1430b {
    public static final String o = z.e("GreedyScheduler");
    public final Context a;
    public final a c;
    public boolean d;
    public final C1433e g;
    public final androidx.work.impl.model.c h;
    public final C1422c i;
    public Boolean k;
    public final m l;
    public final androidx.work.impl.utils.taskexecutor.a m;
    public final d n;
    public final HashMap b = new HashMap();
    public final Object e = new Object();
    public final u f = new u(new y0(2));
    public final HashMap j = new HashMap();

    public c(Context context, C1422c c1422c, androidx.work.impl.constraints.trackers.j jVar, C1433e c1433e, androidx.work.impl.model.c launcher, androidx.work.impl.utils.taskexecutor.a aVar) {
        this.a = context;
        h runnableScheduler = c1422c.g;
        this.c = new a(this, runnableScheduler, c1422c.d);
        Intrinsics.checkNotNullParameter(runnableScheduler, "runnableScheduler");
        Intrinsics.checkNotNullParameter(launcher, "launcher");
        long millis = TimeUnit.MINUTES.toMillis(90L);
        Intrinsics.checkNotNullParameter(runnableScheduler, "runnableScheduler");
        Intrinsics.checkNotNullParameter(launcher, "launcher");
        d dVar = new d();
        dVar.b = runnableScheduler;
        dVar.c = launcher;
        dVar.a = millis;
        dVar.d = new Object();
        dVar.e = new LinkedHashMap();
        this.n = dVar;
        this.m = aVar;
        this.l = new m(jVar);
        this.i = c1422c;
        this.g = c1433e;
        this.h = launcher;
    }

    @Override // androidx.work.impl.InterfaceC1435g
    public final void a(q... qVarArr) {
        long jMax;
        if (this.k == null) {
            this.k = Boolean.valueOf(i.a(this.a, this.i));
        }
        if (!this.k.booleanValue()) {
            z.c().d(o, "Ignoring schedule request in a secondary process");
            return;
        }
        if (!this.d) {
            this.g.a(this);
            this.d = true;
        }
        HashSet hashSet = new HashSet();
        HashSet hashSet2 = new HashSet();
        for (q spec : qVarArr) {
            if (!this.f.c(A2.a(spec))) {
                synchronized (this.e) {
                    try {
                        androidx.work.impl.model.j jVarA = A2.a(spec);
                        b bVar = (b) this.j.get(jVarA);
                        if (bVar == null) {
                            int i = spec.k;
                            this.i.d.getClass();
                            bVar = new b(i, System.currentTimeMillis());
                            this.j.put(jVarA, bVar);
                        }
                        jMax = (Math.max((spec.k - bVar.a) - 5, 0) * 30000) + bVar.b;
                    } finally {
                    }
                }
                long jMax2 = Math.max(spec.a(), jMax);
                this.i.d.getClass();
                long jCurrentTimeMillis = System.currentTimeMillis();
                if (spec.b == N.a) {
                    if (jCurrentTimeMillis < jMax2) {
                        a aVar = this.c;
                        if (aVar != null) {
                            HashMap map = aVar.d;
                            Runnable runnable = (Runnable) map.remove(spec.a);
                            h hVar = aVar.b;
                            if (runnable != null) {
                                hVar.a.removeCallbacks(runnable);
                            }
                            androidx.camera.core.impl.utils.futures.h hVar2 = new androidx.camera.core.impl.utils.futures.h(aVar, false, spec, 6);
                            map.put(spec.a, hVar2);
                            aVar.c.getClass();
                            hVar.a.postDelayed(hVar2, jMax2 - System.currentTimeMillis());
                        }
                    } else if (spec.b()) {
                        C1425f c1425f = spec.j;
                        if (c1425f.d) {
                            z zVarC = z.c();
                            spec.toString();
                            zVarC.getClass();
                        } else if (c1425f.a()) {
                            z zVarC2 = z.c();
                            spec.toString();
                            zVarC2.getClass();
                        } else {
                            hashSet.add(spec);
                            hashSet2.add(spec.a);
                        }
                    } else if (!this.f.c(A2.a(spec))) {
                        z.c().getClass();
                        u uVar = this.f;
                        uVar.getClass();
                        Intrinsics.checkNotNullParameter(spec, "spec");
                        androidx.work.impl.j workSpecId = uVar.t(A2.a(spec));
                        this.n.j(workSpecId);
                        androidx.work.impl.model.c cVar = this.h;
                        cVar.getClass();
                        Intrinsics.checkNotNullParameter(workSpecId, "workSpecId");
                        Intrinsics.checkNotNullParameter(workSpecId, "workSpecId");
                        ((androidx.work.impl.utils.taskexecutor.a) cVar.c).a(new RunnableC0130g(cVar, workSpecId, null, 17));
                    }
                }
            }
        }
        synchronized (this.e) {
            try {
                if (!hashSet.isEmpty()) {
                    TextUtils.join(",", hashSet2);
                    z.c().getClass();
                    Iterator it2 = hashSet.iterator();
                    while (it2.hasNext()) {
                        q qVar = (q) it2.next();
                        androidx.work.impl.model.j jVarA2 = A2.a(qVar);
                        if (!this.b.containsKey(jVarA2)) {
                            this.b.put(jVarA2, o.a(this.l, qVar, ((androidx.work.impl.utils.taskexecutor.c) this.m).b, this));
                        }
                    }
                }
            } finally {
            }
        }
    }

    @Override // androidx.work.impl.InterfaceC1430b
    public final void b(androidx.work.impl.model.j jVar, boolean z) {
        InterfaceC5025j0 interfaceC5025j0;
        androidx.work.impl.j jVarQ = this.f.q(jVar);
        if (jVarQ != null) {
            this.n.a(jVarQ);
        }
        synchronized (this.e) {
            interfaceC5025j0 = (InterfaceC5025j0) this.b.remove(jVar);
        }
        if (interfaceC5025j0 != null) {
            z zVarC = z.c();
            Objects.toString(jVar);
            zVarC.getClass();
            interfaceC5025j0.j(null);
        }
        if (z) {
            return;
        }
        synchronized (this.e) {
            this.j.remove(jVar);
        }
    }

    @Override // androidx.work.impl.InterfaceC1435g
    public final boolean c() {
        return false;
    }

    @Override // androidx.work.impl.constraints.j
    public final void d(q qVar, androidx.work.impl.constraints.c cVar) {
        androidx.work.impl.model.j jVarA = A2.a(qVar);
        boolean z = cVar instanceof androidx.work.impl.constraints.a;
        androidx.work.impl.model.c cVar2 = this.h;
        d dVar = this.n;
        u uVar = this.f;
        if (!z) {
            z zVarC = z.c();
            jVarA.toString();
            zVarC.getClass();
            androidx.work.impl.j workSpecId = uVar.q(jVarA);
            if (workSpecId != null) {
                dVar.a(workSpecId);
                int i = ((androidx.work.impl.constraints.b) cVar).a;
                cVar2.getClass();
                Intrinsics.checkNotNullParameter(workSpecId, "workSpecId");
                cVar2.z(workSpecId, i);
                return;
            }
            return;
        }
        if (uVar.c(jVarA)) {
            return;
        }
        z zVarC2 = z.c();
        jVarA.toString();
        zVarC2.getClass();
        androidx.work.impl.j workSpecId2 = uVar.t(jVarA);
        dVar.j(workSpecId2);
        cVar2.getClass();
        Intrinsics.checkNotNullParameter(workSpecId2, "workSpecId");
        Intrinsics.checkNotNullParameter(workSpecId2, "workSpecId");
        ((androidx.work.impl.utils.taskexecutor.a) cVar2.c).a(new RunnableC0130g(cVar2, workSpecId2, null, 17));
    }

    @Override // androidx.work.impl.InterfaceC1435g
    public final void e(String str) {
        Runnable runnable;
        if (this.k == null) {
            this.k = Boolean.valueOf(i.a(this.a, this.i));
        }
        if (!this.k.booleanValue()) {
            z.c().d(o, "Ignoring schedule request in non-main process");
            return;
        }
        if (!this.d) {
            this.g.a(this);
            this.d = true;
        }
        z.c().getClass();
        a aVar = this.c;
        if (aVar != null && (runnable = (Runnable) aVar.d.remove(str)) != null) {
            aVar.b.a.removeCallbacks(runnable);
        }
        for (androidx.work.impl.j workSpecId : this.f.r(str)) {
            this.n.a(workSpecId);
            androidx.work.impl.model.c cVar = this.h;
            cVar.getClass();
            Intrinsics.checkNotNullParameter(workSpecId, "workSpecId");
            cVar.z(workSpecId, -512);
        }
    }
}

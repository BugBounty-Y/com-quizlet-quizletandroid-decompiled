package com.google.firebase.perf.transport;

import android.content.Context;
import android.content.pm.PackageManager;
import androidx.camera.camera2.internal.C0148z;
import com.google.firebase.crashlytics.internal.common.i;
import com.google.firebase.h;
import com.google.firebase.perf.v1.C3971a;
import com.google.firebase.perf.v1.C3972b;
import com.google.firebase.perf.v1.C3975e;
import com.google.firebase.perf.v1.C3977g;
import java.lang.ref.WeakReference;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.TimeUnit;

/* loaded from: classes2.dex */
public final /* synthetic */ class e implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ f b;

    public /* synthetic */ e(f fVar, int i) {
        this.a = i;
        this.b = fVar;
    }

    @Override // java.lang.Runnable
    public final void run() {
        com.google.firebase.perf.config.f fVar;
        String str;
        switch (this.a) {
            case 0:
                f fVar2 = this.b;
                d dVar = fVar2.l;
                boolean z = fVar2.q;
                dVar.d.a(z);
                dVar.e.a(z);
                return;
            default:
                f fVar3 = this.b;
                h hVar = fVar3.d;
                hVar.a();
                Context context = hVar.a;
                fVar3.j = context;
                fVar3.o = context.getPackageName();
                fVar3.k = com.google.firebase.perf.config.a.e();
                fVar3.l = new d(fVar3.j, new C0148z(100L, 1L, TimeUnit.MINUTES));
                fVar3.m = com.google.firebase.perf.application.c.a();
                com.google.firebase.inject.b bVar = fVar3.g;
                com.google.firebase.perf.config.a aVar = fVar3.k;
                aVar.getClass();
                com.google.firebase.perf.config.f fVar4 = com.google.firebase.perf.config.f.b;
                synchronized (com.google.firebase.perf.config.f.class) {
                    try {
                        if (com.google.firebase.perf.config.f.b == null) {
                            com.google.firebase.perf.config.f.b = new com.google.firebase.perf.config.f();
                        }
                        fVar = com.google.firebase.perf.config.f.b;
                    } catch (Throwable th) {
                        throw th;
                    }
                }
                fVar.getClass();
                Long l = (Long) aVar.a.getRemoteConfigValueOrDefault("fpr_log_source", -1L);
                l.getClass();
                Map map = com.google.firebase.perf.config.f.c;
                if (!map.containsKey(l) || (str = (String) map.get(l)) == null) {
                    com.google.firebase.perf.util.d dVarD = aVar.d(fVar);
                    str = dVarD.b() ? (String) dVarD.a() : "FIREPERF";
                } else {
                    aVar.c.f("com.google.firebase.perf.LogSourceName", str);
                }
                fVar3.h = new a(bVar, str);
                com.google.firebase.perf.application.c cVar = fVar3.m;
                WeakReference weakReference = new WeakReference(f.s);
                synchronized (cVar.f) {
                    cVar.f.add(weakReference);
                }
                C3975e c3975eH = C3977g.H();
                fVar3.n = c3975eH;
                h hVar2 = fVar3.d;
                hVar2.a();
                String str2 = hVar2.c.b;
                c3975eH.k();
                C3977g.w((C3977g) c3975eH.b, str2);
                C3971a c3971aC = C3972b.C();
                String str3 = fVar3.o;
                c3971aC.k();
                C3972b.w((C3972b) c3971aC.b, str3);
                c3971aC.k();
                C3972b.x((C3972b) c3971aC.b);
                Context context2 = fVar3.j;
                String str4 = "";
                try {
                    String str5 = context2.getPackageManager().getPackageInfo(context2.getPackageName(), 0).versionName;
                    if (str5 != null) {
                        str4 = str5;
                    }
                } catch (PackageManager.NameNotFoundException unused) {
                }
                c3971aC.k();
                C3972b.y((C3972b) c3971aC.b, str4);
                c3975eH.k();
                C3977g.A((C3977g) c3975eH.b, (C3972b) c3971aC.h());
                fVar3.c.set(true);
                while (true) {
                    ConcurrentLinkedQueue concurrentLinkedQueue = fVar3.b;
                    if (concurrentLinkedQueue.isEmpty()) {
                        return;
                    }
                    b bVar2 = (b) concurrentLinkedQueue.poll();
                    if (bVar2 != null) {
                        fVar3.i.execute(new i(8, fVar3, bVar2));
                    }
                }
                break;
        }
    }
}

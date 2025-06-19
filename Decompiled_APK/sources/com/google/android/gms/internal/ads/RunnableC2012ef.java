package com.google.android.gms.internal.ads;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import org.json.JSONObject;

/* renamed from: com.google.android.gms.internal.ads.ef, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class RunnableC2012ef implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ BinderC2144hf b;
    public final /* synthetic */ Runnable c;

    public /* synthetic */ RunnableC2012ef(BinderC2144hf binderC2144hf, Runnable runnable, int i) {
        this.a = i;
        this.b = binderC2144hf;
        this.c = runnable;
    }

    @Override // java.lang.Runnable
    public final void run() {
        zzfcw zzfcwVar;
        Runnable runnable = this.c;
        BinderC2144hf binderC2144hf = this.b;
        switch (this.a) {
            case 0:
                int i = BinderC2144hf.q;
                com.google.android.gms.common.internal.u.d("Adapters must be initialized on the main thread.");
                HashMap map = com.google.android.gms.ads.internal.j.C.h.d().n().c;
                if (map.isEmpty()) {
                    return;
                }
                if (runnable != null) {
                    try {
                        runnable.run();
                    } catch (Throwable th) {
                        com.google.android.gms.ads.internal.util.client.i.i("Could not initialize rewarded ads.", th);
                        return;
                    }
                }
                if (((InterfaceC2825xa) ((AtomicReference) binderC2144hf.c.a.d).get()) != null) {
                    HashMap map2 = new HashMap();
                    Iterator it2 = map.values().iterator();
                    while (it2.hasNext()) {
                        for (C2653ta c2653ta : ((C2696ua) it2.next()).a) {
                            String str = c2653ta.b;
                            for (String str2 : c2653ta.a) {
                                if (!map2.containsKey(str2)) {
                                    map2.put(str2, new ArrayList());
                                }
                                if (str != null) {
                                    ((List) map2.get(str2)).add(str);
                                }
                            }
                        }
                    }
                    JSONObject jSONObject = new JSONObject();
                    for (Map.Entry entry : map2.entrySet()) {
                        String str3 = (String) entry.getKey();
                        try {
                            C2880ym c2880ymA = binderC2144hf.d.a(str3, jSONObject);
                            if (c2880ymA != null) {
                                C2369mq c2369mq = (C2369mq) c2880ymA.b;
                                boolean zA = c2369mq.a();
                                InterfaceC2911za interfaceC2911za = c2369mq.a;
                                if (!zA) {
                                    try {
                                        if (interfaceC2911za.H()) {
                                            try {
                                                interfaceC2911za.d3(new com.google.android.gms.dynamic.b(binderC2144hf.a), (Sm) c2880ymA.c, (List) entry.getValue());
                                                com.google.android.gms.ads.internal.util.client.i.d("Initialized rewarded video mediation adapter " + str3);
                                            } finally {
                                            }
                                        }
                                    } finally {
                                    }
                                }
                            }
                        } catch (zzfcw e) {
                            com.google.android.gms.ads.internal.util.client.i.i("Failed to initialize rewarded video mediation adapter \"" + str3 + "\"", e);
                        }
                    }
                    return;
                }
                return;
            default:
                AbstractC2270kd.f.execute(new RunnableC2012ef(binderC2144hf, runnable, 0));
                return;
        }
    }
}

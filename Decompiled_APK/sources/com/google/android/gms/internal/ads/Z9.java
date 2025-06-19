package com.google.android.gms.internal.ads;

import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/* loaded from: classes2.dex */
public final class Z9 implements InterfaceC2389n9 {
    public final /* synthetic */ long a;
    public final /* synthetic */ C1964da b;
    public final /* synthetic */ V9 c;
    public final /* synthetic */ C2007ea d;

    public Z9(C2007ea c2007ea, long j, C1964da c1964da, V9 v9) {
        this.a = j;
        this.b = c1964da;
        this.c = v9;
        this.d = c2007ea;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2389n9
    public final void e(Object obj, Map map) {
        com.google.android.gms.ads.internal.j.C.k.getClass();
        com.google.android.gms.ads.internal.util.A.l("onGmsg /jsLoaded. JsLoaded latency is " + (System.currentTimeMillis() - this.a) + " ms.");
        com.google.android.gms.ads.internal.util.A.l("loadJavascriptEngine > /jsLoaded handler: Trying to acquire lock");
        C2007ea c2007ea = this.d;
        synchronized (c2007ea.c) {
            com.google.android.gms.ads.internal.util.A.l("loadJavascriptEngine > /jsLoaded handler: Lock acquired");
            C1964da c1964da = this.b;
            if (((AtomicInteger) c1964da.c).get() != -1 && ((AtomicInteger) c1964da.c).get() != 1) {
                c2007ea.b = 0;
                V9 v9 = this.c;
                v9.q("/log", AbstractC2346m9.g);
                v9.q("/result", AbstractC2346m9.o);
                ((C2313ld) c1964da.b).c(v9);
                c2007ea.g = c1964da;
                com.google.android.gms.ads.internal.util.A.l("Successfully loaded JS Engine.");
                com.google.android.gms.ads.internal.util.A.l("loadJavascriptEngine > /jsLoaded handler: Lock released");
                return;
            }
            com.google.android.gms.ads.internal.util.A.l("loadJavascriptEngine > /jsLoaded handler: Lock released, the promise is already settled");
        }
    }
}

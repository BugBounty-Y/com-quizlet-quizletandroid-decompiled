package com.google.android.gms.internal.ads;

import java.util.ArrayList;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;

/* loaded from: classes2.dex */
public final /* synthetic */ class Y9 implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ C1964da b;
    public final /* synthetic */ V9 c;
    public final /* synthetic */ ArrayList d;
    public final /* synthetic */ long e;
    public final /* synthetic */ C2007ea f;

    public /* synthetic */ Y9(C2007ea c2007ea, C1964da c1964da, V9 v9, ArrayList arrayList, long j, int i) {
        this.a = i;
        this.f = c2007ea;
        this.b = c1964da;
        this.c = v9;
        this.d = arrayList;
        this.e = j;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                C2007ea c2007ea = this.f;
                C1964da c1964da = this.b;
                V9 v9 = this.c;
                ArrayList arrayList = this.d;
                long j = this.e;
                com.google.android.gms.ads.internal.util.A.l("loadJavascriptEngine > newEngine.setLoadedListener(postDelayed): Trying to acquire lock");
                synchronized (c2007ea.c) {
                    try {
                        com.google.android.gms.ads.internal.util.A.l("loadJavascriptEngine > newEngine.setLoadedListener(postDelayed): Lock acquired");
                        if (((AtomicInteger) c1964da.c).get() != -1 && ((AtomicInteger) c1964da.c).get() != 1) {
                            C2601s7 c2601s7 = AbstractC2773w7.J7;
                            com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
                            if (((Boolean) rVar.c.a(c2601s7)).booleanValue()) {
                                c1964da.t("SdkJavascriptFactory.loadJavascriptEngine.setLoadedListener", new TimeoutException("Unable to receive /jsLoaded GMSG."));
                            } else {
                                c1964da.s();
                            }
                            AbstractC2270kd.f.execute(new X9(v9, 0));
                            String strValueOf = String.valueOf(rVar.c.a(AbstractC2773w7.c));
                            int i = ((AtomicInteger) c1964da.c).get();
                            int i2 = c2007ea.b;
                            String strValueOf2 = String.valueOf(arrayList.get(0));
                            com.google.android.gms.ads.internal.j.C.k.getClass();
                            com.google.android.gms.ads.internal.util.A.l("Could not receive /jsLoaded in " + strValueOf + " ms. JS engine session reference status(onEngLoadedTimeout) is " + i + ". Update status(onEngLoadedTimeout) is " + i2 + ". LoadNewJavascriptEngine(onEngLoadedTimeout) latency is " + strValueOf2 + " ms. Total latency(onEngLoadedTimeout) is " + (System.currentTimeMillis() - j) + " ms. Rejecting.");
                            com.google.android.gms.ads.internal.util.A.l("loadJavascriptEngine > newEngine.setLoadedListener(postDelayed): Lock released");
                            return;
                        }
                        com.google.android.gms.ads.internal.util.A.l("loadJavascriptEngine > newEngine.setLoadedListener(postDelayed): Lock released, the promise is already settled");
                        return;
                    } finally {
                    }
                }
            default:
                com.google.android.gms.ads.internal.util.A.l("loadJavascriptEngine > ADMOB_UI_HANDLER.postDelayed: Trying to acquire lock");
                C2007ea c2007ea2 = this.f;
                synchronized (c2007ea2.c) {
                    try {
                        com.google.android.gms.ads.internal.util.A.l("loadJavascriptEngine > ADMOB_UI_HANDLER.postDelayed: Lock acquired");
                        C1964da c1964da2 = this.b;
                        if (((AtomicInteger) c1964da2.c).get() != -1 && ((AtomicInteger) c1964da2.c).get() != 1) {
                            C2601s7 c2601s72 = AbstractC2773w7.J7;
                            com.google.android.gms.ads.internal.client.r rVar2 = com.google.android.gms.ads.internal.client.r.d;
                            if (((Boolean) rVar2.c.a(c2601s72)).booleanValue()) {
                                c1964da2.t("SdkJavascriptFactory.loadJavascriptEngine.Runnable", new TimeoutException("Unable to fully load JS engine."));
                            } else {
                                c1964da2.s();
                            }
                            AbstractC2270kd.f.execute(new X9(this.c, 1));
                            String strValueOf3 = String.valueOf(rVar2.c.a(AbstractC2773w7.d));
                            int i3 = ((AtomicInteger) c1964da2.c).get();
                            int i4 = c2007ea2.b;
                            ArrayList arrayList2 = this.d;
                            String strConcat = arrayList2.isEmpty() ? ". Still waiting for the engine to be loaded" : ". While waiting for the /jsLoaded gmsg, observed the loadNewJavascriptEngine latency is ".concat(String.valueOf(arrayList2.get(0)));
                            com.google.android.gms.ads.internal.j.C.k.getClass();
                            com.google.android.gms.ads.internal.util.A.l("Could not finish the full JS engine loading in " + strValueOf3 + " ms. JS engine session reference status(fullLoadTimeout) is " + i3 + ". Update status(fullLoadTimeout) is " + i4 + strConcat + " ms. Total latency(fullLoadTimeout) is " + (System.currentTimeMillis() - this.e) + " ms at timeout. Rejecting.");
                            com.google.android.gms.ads.internal.util.A.l("loadJavascriptEngine > ADMOB_UI_HANDLER.postDelayed: Lock released");
                            return;
                        }
                        com.google.android.gms.ads.internal.util.A.l("loadJavascriptEngine > ADMOB_UI_HANDLER.postDelayed: Lock released, the promise is already settled");
                        return;
                    } finally {
                    }
                }
        }
    }
}

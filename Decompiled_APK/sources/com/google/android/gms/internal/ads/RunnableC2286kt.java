package com.google.android.gms.internal.ads;

import android.content.Context;
import android.content.Intent;
import java.util.ArrayList;

/* renamed from: com.google.android.gms.internal.ads.kt, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class RunnableC2286kt implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ Tm b;
    public final /* synthetic */ Runnable c;

    public /* synthetic */ RunnableC2286kt(Tm tm, Runnable runnable, int i) {
        this.a = i;
        this.b = tm;
        this.c = runnable;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                try {
                    this.c.run();
                    return;
                } catch (RuntimeException e) {
                    ((Gw) this.b.d).a("error caused by ", e);
                    return;
                }
            default:
                Tm tm = this.b;
                Runnable runnable = this.c;
                if (((Ys) tm.j) != null || tm.a) {
                    if (!tm.a) {
                        runnable.run();
                        return;
                    }
                    ((Gw) tm.d).c("Waiting to bind to the service.", new Object[0]);
                    ArrayList arrayList = (ArrayList) tm.f;
                    synchronized (arrayList) {
                        arrayList.add(runnable);
                    }
                    return;
                }
                ((Gw) tm.d).c("Initiate binding to the service.", new Object[0]);
                ArrayList arrayList2 = (ArrayList) tm.f;
                synchronized (arrayList2) {
                    arrayList2.add(runnable);
                }
                ServiceConnectionC2372mt serviceConnectionC2372mt = new ServiceConnectionC2372mt(tm);
                tm.i = serviceConnectionC2372mt;
                tm.a = true;
                if (((Context) tm.b).bindService((Intent) tm.g, serviceConnectionC2372mt, 1)) {
                    return;
                }
                ((Gw) tm.d).c("Failed to bind to the service.", new Object[0]);
                tm.a = false;
                ArrayList arrayList3 = (ArrayList) tm.f;
                synchronized (arrayList3) {
                    arrayList3.clear();
                }
                return;
        }
    }
}

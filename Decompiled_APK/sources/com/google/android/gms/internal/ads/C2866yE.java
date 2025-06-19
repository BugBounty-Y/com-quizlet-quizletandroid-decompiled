package com.google.android.gms.internal.ads;

import android.os.Handler;
import android.os.Looper;
import android.os.RemoteException;
import java.io.IOException;
import java.util.Iterator;
import java.util.concurrent.CopyOnWriteArrayList;

/* renamed from: com.google.android.gms.internal.ads.yE, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2866yE {
    public final C2093gF a;
    public final CopyOnWriteArrayList b;

    public /* synthetic */ C2866yE(CopyOnWriteArrayList copyOnWriteArrayList, C2093gF c2093gF) {
        this.b = copyOnWriteArrayList;
        this.a = c2093gF;
    }

    public void a(InterfaceC2491pj interfaceC2491pj) throws RemoteException, IOException {
        Iterator it2 = this.b.iterator();
        while (it2.hasNext()) {
            C2223jF c2223jF = (C2223jF) it2.next();
            RunnableC2793wl runnableC2793wl = new RunnableC2793wl(25, interfaceC2491pj, c2223jF.b);
            Handler handler = c2223jF.a;
            String str = Yo.a;
            Looper looper = handler.getLooper();
            if (looper.getThread().isAlive()) {
                if (looper == Looper.myLooper()) {
                    runnableC2793wl.run();
                } else {
                    handler.post(runnableC2793wl);
                }
            }
        }
    }
}

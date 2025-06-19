package com.google.android.play.core.review.internal;

import android.content.Context;
import android.content.Intent;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.IBinder;
import android.os.RemoteException;
import com.android.billingclient.api.C1472a;
import com.android.billingclient.api.u;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.concurrent.atomic.AtomicInteger;

/* loaded from: classes2.dex */
public final class j {
    public static final HashMap n = new HashMap();
    public final Context a;
    public final C1472a b;
    public boolean g;
    public final Intent h;
    public u l;
    public d m;
    public final ArrayList d = new ArrayList();
    public final HashSet e = new HashSet();
    public final Object f = new Object();
    public final f j = new IBinder.DeathRecipient() { // from class: com.google.android.play.core.review.internal.f
        @Override // android.os.IBinder.DeathRecipient
        public final void binderDied() {
            j jVar = this.a;
            jVar.b.a("reportBinderDeath", new Object[0]);
            if (jVar.i.get() != null) {
                throw new ClassCastException();
            }
            jVar.b.a("%s : Binder has died.", jVar.c);
            Iterator it2 = jVar.d.iterator();
            while (it2.hasNext()) {
                e eVar = (e) it2.next();
                RemoteException remoteException = new RemoteException(String.valueOf(jVar.c).concat(" : Binder has died."));
                com.google.android.gms.tasks.f fVar = eVar.a;
                if (fVar != null) {
                    fVar.c(remoteException);
                }
            }
            jVar.d.clear();
            synchronized (jVar.f) {
                jVar.c();
            }
        }
    };
    public final AtomicInteger k = new AtomicInteger(0);
    public final String c = "com.google.android.finsky.inappreviewservice.InAppReviewService";
    public final WeakReference i = new WeakReference(null);

    /* JADX WARN: Type inference failed for: r0v3, types: [com.google.android.play.core.review.internal.f] */
    public j(Context context, C1472a c1472a, Intent intent) {
        this.a = context;
        this.b = c1472a;
        this.h = intent;
    }

    public static void b(j jVar, i iVar) {
        d dVar = jVar.m;
        ArrayList arrayList = jVar.d;
        C1472a c1472a = jVar.b;
        if (dVar != null || jVar.g) {
            if (!jVar.g) {
                iVar.run();
                return;
            } else {
                c1472a.a("Waiting to bind to the service.", new Object[0]);
                arrayList.add(iVar);
                return;
            }
        }
        c1472a.a("Initiate binding to the service.", new Object[0]);
        arrayList.add(iVar);
        u uVar = new u(jVar, 1);
        jVar.l = uVar;
        jVar.g = true;
        if (jVar.a.bindService(jVar.h, uVar, 1)) {
            return;
        }
        c1472a.a("Failed to bind to the service.", new Object[0]);
        jVar.g = false;
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            e eVar = (e) it2.next();
            zzu zzuVar = new zzu();
            com.google.android.gms.tasks.f fVar = eVar.a;
            if (fVar != null) {
                fVar.c(zzuVar);
            }
        }
        arrayList.clear();
    }

    public final Handler a() {
        Handler handler;
        HashMap map = n;
        synchronized (map) {
            try {
                if (!map.containsKey(this.c)) {
                    HandlerThread handlerThread = new HandlerThread(this.c, 10);
                    handlerThread.start();
                    map.put(this.c, new Handler(handlerThread.getLooper()));
                }
                handler = (Handler) map.get(this.c);
            } catch (Throwable th) {
                throw th;
            }
        }
        return handler;
    }

    public final void c() {
        HashSet hashSet = this.e;
        Iterator it2 = hashSet.iterator();
        while (it2.hasNext()) {
            ((com.google.android.gms.tasks.f) it2.next()).c(new RemoteException(String.valueOf(this.c).concat(" : Binder has died.")));
        }
        hashSet.clear();
    }
}

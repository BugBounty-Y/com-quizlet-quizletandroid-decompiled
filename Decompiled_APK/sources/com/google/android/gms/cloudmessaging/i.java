package com.google.android.gms.cloudmessaging;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.IBinder;
import android.os.Looper;
import android.os.Messenger;
import android.util.Log;
import android.util.SparseArray;
import androidx.work.impl.model.v;
import com.google.android.gms.common.internal.u;
import com.google.android.gms.internal.ads.Ls;
import java.util.ArrayDeque;
import java.util.Iterator;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/* loaded from: classes2.dex */
public final class i implements ServiceConnection {
    public int a = 0;
    public final Messenger b;
    public v c;
    public final ArrayDeque d;
    public final SparseArray e;
    public final /* synthetic */ k f;

    public i(k kVar) {
        this.f = kVar;
        Ls ls = new Ls(Looper.getMainLooper(), new com.bumptech.glide.load.resource.gif.f(this, 1), 2);
        Looper.getMainLooper();
        this.b = new Messenger(ls);
        this.d = new ArrayDeque();
        this.e = new SparseArray();
    }

    public final synchronized void a(String str) {
        b(str, null);
    }

    public final synchronized void b(String str, SecurityException securityException) {
        try {
            if (Log.isLoggable("MessengerIpcClient", 3)) {
                "Disconnected: ".concat(String.valueOf(str));
            }
            int i = this.a;
            if (i == 0) {
                throw new IllegalStateException();
            }
            if (i != 1 && i != 2) {
                if (i != 3) {
                    return;
                }
                this.a = 4;
                return;
            }
            Log.isLoggable("MessengerIpcClient", 2);
            this.a = 4;
            com.google.android.gms.common.stats.a.b().c((Context) this.f.c, this);
            zzt zztVar = new zzt(str, securityException);
            Iterator it2 = this.d.iterator();
            while (it2.hasNext()) {
                ((j) it2.next()).b(zztVar);
            }
            this.d.clear();
            for (int i2 = 0; i2 < this.e.size(); i2++) {
                ((j) this.e.valueAt(i2)).b(zztVar);
            }
            this.e.clear();
        } catch (Throwable th) {
            throw th;
        }
    }

    public final synchronized void c() {
        if (this.a == 2 && this.d.isEmpty() && this.e.size() == 0) {
            Log.isLoggable("MessengerIpcClient", 2);
            this.a = 3;
            com.google.android.gms.common.stats.a.b().c((Context) this.f.c, this);
        }
    }

    public final synchronized boolean d(j jVar) {
        int i = this.a;
        if (i != 0) {
            if (i == 1) {
                this.d.add(jVar);
                return true;
            }
            if (i != 2) {
                return false;
            }
            this.d.add(jVar);
            ((ScheduledExecutorService) this.f.d).execute(new h(this, 0));
            return true;
        }
        this.d.add(jVar);
        u.k(this.a == 0);
        Log.isLoggable("MessengerIpcClient", 2);
        this.a = 1;
        Intent intent = new Intent("com.google.android.c2dm.intent.REGISTER");
        intent.setPackage("com.google.android.gms");
        try {
            if (com.google.android.gms.common.stats.a.b().a((Context) this.f.c, intent, this, 1)) {
                ((ScheduledExecutorService) this.f.d).schedule(new h(this, 1), 30L, TimeUnit.SECONDS);
            } else {
                a("Unable to bind to service");
            }
        } catch (SecurityException e) {
            b("Unable to bind to service", e);
        }
        return true;
    }

    @Override // android.content.ServiceConnection
    public final void onServiceConnected(ComponentName componentName, IBinder iBinder) {
        Log.isLoggable("MessengerIpcClient", 2);
        ((ScheduledExecutorService) this.f.d).execute(new com.google.common.util.concurrent.d(20, this, iBinder));
    }

    @Override // android.content.ServiceConnection
    public final void onServiceDisconnected(ComponentName componentName) {
        Log.isLoggable("MessengerIpcClient", 2);
        ((ScheduledExecutorService) this.f.d).execute(new h(this, 2));
    }
}

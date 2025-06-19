package com.google.android.gms.common.internal;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Build;
import android.os.IBinder;
import android.os.StrictMode;
import com.google.android.gms.common.ConnectionResult;
import java.util.HashMap;
import java.util.Iterator;
import java.util.concurrent.Executor;

/* loaded from: classes2.dex */
public final class C implements ServiceConnection {
    public final HashMap a = new HashMap();
    public int b = 2;
    public boolean c;
    public IBinder d;
    public final B e;
    public ComponentName f;
    public final /* synthetic */ E g;

    public C(E e, B b) {
        this.g = e;
        this.e = b;
    }

    public final ConnectionResult a(String str, Executor executor) throws Throwable {
        try {
            Intent intentA = v.a(this.g.b, this.e);
            this.b = 3;
            StrictMode.VmPolicy vmPolicy = StrictMode.getVmPolicy();
            if (Build.VERSION.SDK_INT >= 31) {
                StrictMode.setVmPolicy(com.google.android.gms.common.util.g.a(new StrictMode.VmPolicy.Builder(vmPolicy)).build());
            }
            try {
                E e = this.g;
                com.google.android.gms.common.stats.a aVar = e.d;
                Context context = e.b;
                B b = this.e;
                try {
                    boolean zD = aVar.d(context, str, intentA, this, 4225, executor);
                    this.c = zD;
                    if (zD) {
                        e.c.sendMessageDelayed(e.c.obtainMessage(1, b), e.f);
                        ConnectionResult connectionResult = ConnectionResult.e;
                        StrictMode.setVmPolicy(vmPolicy);
                        return connectionResult;
                    }
                    this.b = 2;
                    try {
                        e.d.c(e.b, this);
                    } catch (IllegalArgumentException unused) {
                    }
                    ConnectionResult connectionResult2 = new ConnectionResult(16);
                    StrictMode.setVmPolicy(vmPolicy);
                    return connectionResult2;
                } catch (Throwable th) {
                    th = th;
                    Throwable th2 = th;
                    StrictMode.setVmPolicy(vmPolicy);
                    throw th2;
                }
            } catch (Throwable th3) {
                th = th3;
            }
        } catch (zzaf e2) {
            return e2.a;
        }
    }

    @Override // android.content.ServiceConnection
    public final void onBindingDied(ComponentName componentName) {
        onServiceDisconnected(componentName);
    }

    @Override // android.content.ServiceConnection
    public final void onServiceConnected(ComponentName componentName, IBinder iBinder) {
        E e = this.g;
        synchronized (e.a) {
            try {
                e.c.removeMessages(1, this.e);
                this.d = iBinder;
                this.f = componentName;
                Iterator it2 = this.a.values().iterator();
                while (it2.hasNext()) {
                    ((ServiceConnection) it2.next()).onServiceConnected(componentName, iBinder);
                }
                this.b = 1;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // android.content.ServiceConnection
    public final void onServiceDisconnected(ComponentName componentName) {
        E e = this.g;
        synchronized (e.a) {
            try {
                e.c.removeMessages(1, this.e);
                this.d = null;
                this.f = componentName;
                Iterator it2 = this.a.values().iterator();
                while (it2.hasNext()) {
                    ((ServiceConnection) it2.next()).onServiceDisconnected(componentName);
                }
                this.b = 2;
            } catch (Throwable th) {
                throw th;
            }
        }
    }
}

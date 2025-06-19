package com.google.android.gms.common.internal;

import android.content.Context;
import android.content.ServiceConnection;
import android.os.HandlerThread;
import android.os.Looper;
import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.internal.ads.Ls;
import java.util.HashMap;
import java.util.concurrent.Executor;

/* loaded from: classes2.dex */
public final class E {
    public static final Object g = new Object();
    public static E h;
    public static HandlerThread i;
    public final HashMap a = new HashMap();
    public final Context b;
    public volatile Ls c;
    public final com.google.android.gms.common.stats.a d;
    public final long e;
    public final long f;

    public E(Context context, Looper looper) {
        D d = new D(this);
        this.b = context.getApplicationContext();
        Ls ls = new Ls(looper, d, 3);
        Looper.getMainLooper();
        this.c = ls;
        this.d = com.google.android.gms.common.stats.a.b();
        this.e = 5000L;
        this.f = 300000L;
    }

    public static E a(Context context) {
        synchronized (g) {
            try {
                if (h == null) {
                    h = new E(context.getApplicationContext(), context.getMainLooper());
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        return h;
    }

    public final ConnectionResult b(B b, y yVar, String str, Executor executor) {
        HashMap map = this.a;
        synchronized (map) {
            try {
                C c = (C) map.get(b);
                ConnectionResult connectionResultA = null;
                if (executor == null) {
                    executor = null;
                }
                if (c == null) {
                    c = new C(this, b);
                    c.a.put(yVar, yVar);
                    connectionResultA = c.a(str, executor);
                    map.put(b, c);
                } else {
                    this.c.removeMessages(0, b);
                    if (c.a.containsKey(yVar)) {
                        String string = b.toString();
                        StringBuilder sb = new StringBuilder(string.length() + 81);
                        sb.append("Trying to bind a GmsServiceConnection that was already connected before.  config=");
                        sb.append(string);
                        throw new IllegalStateException(sb.toString());
                    }
                    c.a.put(yVar, yVar);
                    int i2 = c.b;
                    if (i2 == 1) {
                        yVar.onServiceConnected(c.f, c.d);
                    } else if (i2 == 2) {
                        connectionResultA = c.a(str, executor);
                    }
                }
                if (c.c) {
                    return ConnectionResult.e;
                }
                if (connectionResultA == null) {
                    connectionResultA = new ConnectionResult(-1);
                }
                return connectionResultA;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public final void c(String str, ServiceConnection serviceConnection, boolean z) {
        B b = new B(str, z);
        u.i(serviceConnection, "ServiceConnection must not be null");
        HashMap map = this.a;
        synchronized (map) {
            try {
                C c = (C) map.get(b);
                if (c == null) {
                    String string = b.toString();
                    StringBuilder sb = new StringBuilder(string.length() + 50);
                    sb.append("Nonexistent connection status for service config: ");
                    sb.append(string);
                    throw new IllegalStateException(sb.toString());
                }
                if (!c.a.containsKey(serviceConnection)) {
                    String string2 = b.toString();
                    StringBuilder sb2 = new StringBuilder(string2.length() + 76);
                    sb2.append("Trying to unbind a GmsServiceConnection  that was not bound before.  config=");
                    sb2.append(string2);
                    throw new IllegalStateException(sb2.toString());
                }
                c.a.remove(serviceConnection);
                if (c.a.isEmpty()) {
                    this.c.sendMessageDelayed(this.c.obtainMessage(0, b), this.e);
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }
}

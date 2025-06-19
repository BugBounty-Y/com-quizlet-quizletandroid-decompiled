package com.google.firebase.messaging;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.IBinder;
import android.util.Log;
import java.util.ArrayDeque;
import java.util.Objects;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/* loaded from: classes2.dex */
public final class G implements ServiceConnection {
    public final Context a;
    public final Intent b;
    public final ScheduledThreadPoolExecutor c;
    public final ArrayDeque d;
    public E e;
    public boolean f;

    public G(Context context) {
        ScheduledThreadPoolExecutor scheduledThreadPoolExecutor = new ScheduledThreadPoolExecutor(1);
        scheduledThreadPoolExecutor.setKeepAliveTime(40L, TimeUnit.SECONDS);
        scheduledThreadPoolExecutor.allowCoreThreadTimeOut(true);
        this.d = new ArrayDeque();
        this.f = false;
        Context applicationContext = context.getApplicationContext();
        this.a = applicationContext;
        this.b = new Intent("com.google.firebase.MESSAGING_EVENT").setPackage(applicationContext.getPackageName());
        this.c = scheduledThreadPoolExecutor;
    }

    public final synchronized void a() {
        try {
            Log.isLoggable("FirebaseMessaging", 3);
            while (!this.d.isEmpty()) {
                Log.isLoggable("FirebaseMessaging", 3);
                E e = this.e;
                if (e == null || !e.isBinderAlive()) {
                    Log.isLoggable("FirebaseMessaging", 3);
                    if (!this.f) {
                        this.f = true;
                        try {
                        } catch (SecurityException e2) {
                            Log.e("FirebaseMessaging", "Exception while binding the service", e2);
                        }
                        if (!com.google.android.gms.common.stats.a.b().a(this.a, this.b, this, 65)) {
                            Log.e("FirebaseMessaging", "binding to the service failed");
                            this.f = false;
                            while (true) {
                                ArrayDeque arrayDeque = this.d;
                                if (arrayDeque.isEmpty()) {
                                    break;
                                } else {
                                    ((F) arrayDeque.poll()).b.d(null);
                                }
                            }
                        }
                    }
                    return;
                }
                Log.isLoggable("FirebaseMessaging", 3);
                this.e.a((F) this.d.poll());
            }
        } finally {
        }
    }

    public final synchronized com.google.android.gms.tasks.m b(Intent intent) {
        F f;
        Log.isLoggable("FirebaseMessaging", 3);
        f = new F(intent);
        ScheduledThreadPoolExecutor scheduledThreadPoolExecutor = this.c;
        f.b.a.b(scheduledThreadPoolExecutor, new com.google.android.material.search.a(scheduledThreadPoolExecutor.schedule(new com.google.firebase.crashlytics.internal.metadata.q(f, 2), 20L, TimeUnit.SECONDS), 13));
        this.d.add(f);
        a();
        return f.b.a;
    }

    @Override // android.content.ServiceConnection
    public final synchronized void onServiceConnected(ComponentName componentName, IBinder iBinder) {
        try {
            if (Log.isLoggable("FirebaseMessaging", 3)) {
                Objects.toString(componentName);
            }
            this.f = false;
            if (iBinder instanceof E) {
                this.e = (E) iBinder;
                a();
                return;
            }
            Log.e("FirebaseMessaging", "Invalid service connection: " + iBinder);
            while (true) {
                ArrayDeque arrayDeque = this.d;
                if (arrayDeque.isEmpty()) {
                    return;
                } else {
                    ((F) arrayDeque.poll()).b.d(null);
                }
            }
        } catch (Throwable th) {
            throw th;
        }
    }

    @Override // android.content.ServiceConnection
    public final void onServiceDisconnected(ComponentName componentName) {
        if (Log.isLoggable("FirebaseMessaging", 3)) {
            Objects.toString(componentName);
        }
        a();
    }
}

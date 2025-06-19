package com.google.android.gms.common.api.internal;

import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.res.Resources;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Looper;
import android.util.SparseIntArray;
import androidx.collection.C0209g;
import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.common.GoogleApiAvailability;
import com.google.android.gms.common.api.GoogleApiActivity;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.common.internal.RootTelemetryConfiguration;
import com.google.android.gms.common.internal.TelemetryData;
import com.google.android.gms.internal.ads.Ls;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/* renamed from: com.google.android.gms.common.api.internal.e, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1647e implements Handler.Callback {
    public static final Status p = new Status(4, "Sign-out occurred while this API call was in progress.", null, null);
    public static final Status q = new Status(4, "The user must be signed in to make this API call.", null, null);
    public static final Object r = new Object();
    public static C1647e s;
    public TelemetryData c;
    public com.google.android.gms.common.internal.service.b d;
    public final Context e;
    public final GoogleApiAvailability f;
    public final androidx.work.impl.model.c g;
    public final Ls n;
    public volatile boolean o;
    public long a = 10000;
    public boolean b = false;
    public final AtomicInteger h = new AtomicInteger(1);
    public final AtomicInteger i = new AtomicInteger(0);
    public final ConcurrentHashMap j = new ConcurrentHashMap(5, 0.75f, 1);
    public l k = null;
    public final C0209g l = new C0209g(0);
    public final C0209g m = new C0209g(0);

    public C1647e(Context context, Looper looper, GoogleApiAvailability googleApiAvailability) {
        this.o = true;
        this.e = context;
        Ls ls = new Ls(looper, this, 1);
        Looper.getMainLooper();
        this.n = ls;
        this.f = googleApiAvailability;
        this.g = new androidx.work.impl.model.c(googleApiAvailability);
        PackageManager packageManager = context.getPackageManager();
        if (com.google.android.gms.common.util.c.g == null) {
            com.google.android.gms.common.util.c.g = Boolean.valueOf(packageManager.hasSystemFeature("android.hardware.type.automotive"));
        }
        if (com.google.android.gms.common.util.c.g.booleanValue()) {
            this.o = false;
        }
        ls.sendMessage(ls.obtainMessage(6));
    }

    public static void a() {
        synchronized (r) {
            try {
                C1647e c1647e = s;
                if (c1647e != null) {
                    c1647e.i.incrementAndGet();
                    Ls ls = c1647e.n;
                    ls.sendMessageAtFrontOfQueue(ls.obtainMessage(10));
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public static Status c(C1643a c1643a, ConnectionResult connectionResult) {
        String str = (String) c1643a.b.c;
        String strValueOf = String.valueOf(connectionResult);
        return new Status(17, androidx.compose.ui.node.B.j(new StringBuilder(String.valueOf(str).length() + 63 + strValueOf.length()), "API: ", str, " is not available on this device. Connection failed with: ", strValueOf), connectionResult.c, connectionResult);
    }

    public static C1647e d(Context context) {
        C1647e c1647e;
        HandlerThread handlerThread;
        synchronized (r) {
            if (s == null) {
                synchronized (com.google.android.gms.common.internal.E.g) {
                    try {
                        handlerThread = com.google.android.gms.common.internal.E.i;
                        if (handlerThread == null) {
                            HandlerThread handlerThread2 = new HandlerThread("GoogleApiHandler", 9);
                            com.google.android.gms.common.internal.E.i = handlerThread2;
                            handlerThread2.start();
                            handlerThread = com.google.android.gms.common.internal.E.i;
                        }
                    } finally {
                    }
                }
                s = new C1647e(context.getApplicationContext(), handlerThread.getLooper(), GoogleApiAvailability.d);
            }
            c1647e = s;
        }
        return c1647e;
    }

    public final n b(com.google.android.gms.common.api.e eVar) {
        ConcurrentHashMap concurrentHashMap = this.j;
        C1643a c1643a = eVar.f;
        n nVar = (n) concurrentHashMap.get(c1643a);
        if (nVar == null) {
            nVar = new n(this, eVar);
            concurrentHashMap.put(c1643a, nVar);
        }
        if (nVar.b.b()) {
            this.m.add(c1643a);
        }
        nVar.n();
        return nVar;
    }

    public final void e(l lVar) {
        synchronized (r) {
            try {
                if (this.k != lVar) {
                    this.k = lVar;
                    this.l.clear();
                }
                this.l.addAll(lVar.f);
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public final boolean f() {
        int i;
        if (this.b) {
            return false;
        }
        RootTelemetryConfiguration rootTelemetryConfiguration = (RootTelemetryConfiguration) com.google.android.gms.common.internal.i.a().a;
        if (rootTelemetryConfiguration != null && !rootTelemetryConfiguration.b) {
            return false;
        }
        SparseIntArray sparseIntArray = (SparseIntArray) this.g.b;
        synchronized (sparseIntArray) {
            i = sparseIntArray.get(203400000, -1);
        }
        return i == -1 || i == 0;
    }

    public final boolean g(ConnectionResult connectionResult, int i) throws Resources.NotFoundException {
        GoogleApiAvailability googleApiAvailability = this.f;
        googleApiAvailability.getClass();
        Context context = this.e;
        if (!com.google.android.gms.common.wrappers.a.f(context)) {
            int i2 = connectionResult.b;
            PendingIntent activity = connectionResult.c;
            if (!((i2 == 0 || activity == null) ? false : true)) {
                activity = null;
                Intent intentB = googleApiAvailability.b(context, null, i2);
                if (intentB != null) {
                    activity = PendingIntent.getActivity(context, 0, intentB, 201326592);
                }
            }
            if (activity != null) {
                int i3 = GoogleApiActivity.b;
                Intent intent = new Intent(context, (Class<?>) GoogleApiActivity.class);
                intent.putExtra("pending_intent", activity);
                intent.putExtra("failing_client_id", i);
                intent.putExtra("notify_manager", true);
                googleApiAvailability.g(context, i2, PendingIntent.getActivity(context, 0, intent, com.google.android.gms.internal.base.c.a | 134217728));
                return true;
            }
        }
        return false;
    }

    public final void h(ConnectionResult connectionResult, int i) {
        if (g(connectionResult, i)) {
            return;
        }
        Ls ls = this.n;
        ls.sendMessage(ls.obtainMessage(5, i, 0, connectionResult));
    }

    /* JADX WARN: Removed duplicated region for block: B:159:0x031e  */
    @Override // android.os.Handler.Callback
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean handleMessage(android.os.Message r15) {
        /*
            Method dump skipped, instructions count: 1134
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.common.api.internal.C1647e.handleMessage(android.os.Message):boolean");
    }
}

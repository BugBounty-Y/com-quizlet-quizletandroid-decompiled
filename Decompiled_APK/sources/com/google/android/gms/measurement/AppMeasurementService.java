package com.google.android.gms.measurement;

import android.app.Service;
import android.app.job.JobParameters;
import android.content.Context;
import android.content.Intent;
import android.os.IBinder;
import android.os.PowerManager;
import android.util.Log;
import android.util.SparseArray;
import androidx.camera.core.impl.utils.futures.h;
import com.google.android.gms.measurement.internal.BinderC3869g0;
import com.google.android.gms.measurement.internal.G0;
import com.google.android.gms.measurement.internal.I;
import com.google.android.gms.measurement.internal.Y;
import com.google.android.gms.measurement.internal.b1;
import com.google.android.gms.measurement.internal.c1;
import com.google.android.gms.measurement.internal.r1;

/* loaded from: classes2.dex */
public final class AppMeasurementService extends Service implements b1 {
    public c1 a;

    @Override // com.google.android.gms.measurement.internal.b1
    public final boolean a(int i) {
        return stopSelfResult(i);
    }

    @Override // com.google.android.gms.measurement.internal.b1
    public final void b(Intent intent) {
        SparseArray sparseArray = androidx.legacy.content.a.a;
        int intExtra = intent.getIntExtra("androidx.contentpager.content.wakelockid", 0);
        if (intExtra == 0) {
            return;
        }
        SparseArray sparseArray2 = androidx.legacy.content.a.a;
        synchronized (sparseArray2) {
            try {
                PowerManager.WakeLock wakeLock = (PowerManager.WakeLock) sparseArray2.get(intExtra);
                if (wakeLock != null) {
                    wakeLock.release();
                    sparseArray2.remove(intExtra);
                } else {
                    Log.w("WakefulBroadcastReceiv.", "No active wake lock id #" + intExtra);
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // com.google.android.gms.measurement.internal.b1
    public final void c(JobParameters jobParameters) {
        throw new UnsupportedOperationException();
    }

    public final c1 d() {
        if (this.a == null) {
            this.a = new c1(this);
        }
        return this.a;
    }

    @Override // android.app.Service
    public final IBinder onBind(Intent intent) {
        c1 c1VarD = d();
        c1VarD.getClass();
        if (intent == null) {
            Log.e("FA", "onBind called with null intent");
            return null;
        }
        String action = intent.getAction();
        if ("com.google.android.gms.measurement.START".equals(action)) {
            return new BinderC3869g0(r1.o0(c1VarD.a));
        }
        Log.w("FA", "onBind received unknown action: ".concat(String.valueOf(action)));
        return null;
    }

    @Override // android.app.Service
    public final void onCreate() {
        super.onCreate();
        d().a.getClass().getSimpleName().concat(" is starting up.");
    }

    @Override // android.app.Service
    public final void onDestroy() {
        d().a.getClass().getSimpleName().concat(" is shutting down.");
        super.onDestroy();
    }

    @Override // android.app.Service
    public final void onRebind(Intent intent) {
        d();
        if (intent == null) {
            Log.e("FA", "onRebind called with null intent");
        } else {
            "onRebind called. action: ".concat(String.valueOf(intent.getAction()));
        }
    }

    @Override // android.app.Service
    public final int onStartCommand(Intent intent, int i, int i2) {
        c1 c1VarD = d();
        if (intent == null) {
            c1VarD.getClass();
            Log.w("FA", "AppMeasurementService started with null intent");
            return 2;
        }
        Context context = c1VarD.a;
        I i3 = Y.q(context, null, null).i;
        Y.k(i3);
        String action = intent.getAction();
        i3.o.h("Local AppMeasurementService called. startId, action", Integer.valueOf(i2), action);
        if (!"com.google.android.gms.measurement.UPLOAD".equals(action)) {
            return 2;
        }
        G0 g0 = new G0(i2, 1, c1VarD, i3, intent);
        r1 r1VarO0 = r1.o0(context);
        r1VarO0.i().c0(new h(28, r1VarO0, g0));
        return 2;
    }

    @Override // android.app.Service
    public final boolean onUnbind(Intent intent) {
        d();
        if (intent == null) {
            Log.e("FA", "onUnbind called with null intent");
            return true;
        }
        "onUnbind called for intent. action: ".concat(String.valueOf(intent.getAction()));
        return true;
    }
}

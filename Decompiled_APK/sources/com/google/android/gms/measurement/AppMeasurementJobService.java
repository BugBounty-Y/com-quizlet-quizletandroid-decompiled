package com.google.android.gms.measurement;

import android.annotation.TargetApi;
import android.app.job.JobParameters;
import android.app.job.JobService;
import android.content.Context;
import android.content.Intent;
import android.util.Log;
import androidx.camera.core.impl.utils.futures.h;
import androidx.core.provider.k;
import com.comscore.streaming.EventType;
import com.google.android.gms.common.internal.u;
import com.google.android.gms.internal.measurement.C3008j0;
import com.google.android.gms.internal.measurement.V;
import com.google.android.gms.measurement.internal.A0;
import com.google.android.gms.measurement.internal.AbstractC3893t;
import com.google.android.gms.measurement.internal.I;
import com.google.android.gms.measurement.internal.b1;
import com.google.android.gms.measurement.internal.c1;
import com.google.android.gms.measurement.internal.r1;
import com.google.android.material.shape.e;
import java.util.Objects;

@TargetApi(EventType.VIDEO)
/* loaded from: classes2.dex */
public final class AppMeasurementJobService extends JobService implements b1 {
    public c1 a;

    @Override // com.google.android.gms.measurement.internal.b1
    public final boolean a(int i) {
        throw new UnsupportedOperationException();
    }

    @Override // com.google.android.gms.measurement.internal.b1
    public final void b(Intent intent) {
    }

    @Override // com.google.android.gms.measurement.internal.b1
    public final void c(JobParameters jobParameters) {
        jobFinished(jobParameters, false);
    }

    public final c1 d() {
        if (this.a == null) {
            this.a = new c1(this);
        }
        return this.a;
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

    @Override // android.app.job.JobService
    public final boolean onStartJob(JobParameters jobParameters) {
        c1 c1VarD = d();
        c1VarD.getClass();
        String string = jobParameters.getExtras().getString("action");
        "onStartJob received action: ".concat(String.valueOf(string));
        boolean zEquals = Objects.equals(string, "com.google.android.gms.measurement.UPLOAD");
        Context context = c1VarD.a;
        if (zEquals) {
            u.h(string);
            r1 r1VarO0 = r1.o0(context);
            I iC = r1VarO0.c();
            e eVar = r1VarO0.l.f;
            iC.o.g("Local AppMeasurementJobService called. action", string);
            r1VarO0.i().c0(new h(28, r1VarO0, new k(c1VarD, iC, jobParameters, 20)));
        }
        if (!Objects.equals(string, "com.google.android.gms.measurement.SCION_UPLOAD")) {
            return true;
        }
        u.h(string);
        C3008j0 c3008j0F = C3008j0.f(context, null, null, null, null);
        if (!((Boolean) AbstractC3893t.T0.a(null)).booleanValue()) {
            return true;
        }
        A0 a0 = new A0(c1VarD, false, jobParameters, 5);
        c3008j0F.getClass();
        c3008j0F.c(new V(c3008j0F, a0, 1));
        return true;
    }

    @Override // android.app.job.JobService
    public final boolean onStopJob(JobParameters jobParameters) {
        return false;
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

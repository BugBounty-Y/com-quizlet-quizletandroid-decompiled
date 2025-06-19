package com.google.android.gms.measurement.internal;

import android.app.AlarmManager;
import android.app.PendingIntent;
import android.app.job.JobScheduler;
import android.content.Context;
import android.content.Intent;

/* loaded from: classes2.dex */
public final class k1 extends m1 {
    public final AlarmManager e;
    public f1 f;
    public Integer g;

    public k1(r1 r1Var) {
        super(r1Var);
        this.e = (AlarmManager) ((Y) this.b).a.getSystemService("alarm");
    }

    @Override // androidx.compose.animation.core.J0
    public final void Q() {
        T();
        Y y = (Y) this.b;
        I i = y.i;
        Y.k(i);
        i.o.f("Unscheduling upload");
        AlarmManager alarmManager = this.e;
        if (alarmManager != null) {
            Context context = y.a;
            alarmManager.cancel(PendingIntent.getBroadcast(context, 0, new Intent().setClassName(context, "com.google.android.gms.measurement.AppMeasurementReceiver").setAction("com.google.android.gms.measurement.UPLOAD"), com.google.android.gms.internal.measurement.E.a));
        }
        X().a();
        JobScheduler jobScheduler = (JobScheduler) y.a.getSystemService("jobscheduler");
        if (jobScheduler != null) {
            jobScheduler.cancel(W());
        }
    }

    @Override // com.google.android.gms.measurement.internal.m1
    public final void V() {
        Y y = (Y) this.b;
        AlarmManager alarmManager = this.e;
        if (alarmManager != null) {
            Context context = y.a;
            alarmManager.cancel(PendingIntent.getBroadcast(context, 0, new Intent().setClassName(context, "com.google.android.gms.measurement.AppMeasurementReceiver").setAction("com.google.android.gms.measurement.UPLOAD"), com.google.android.gms.internal.measurement.E.a));
        }
        JobScheduler jobScheduler = (JobScheduler) y.a.getSystemService("jobscheduler");
        if (jobScheduler != null) {
            jobScheduler.cancel(W());
        }
    }

    public final int W() {
        if (this.g == null) {
            this.g = Integer.valueOf("measurement".concat(String.valueOf(((Y) this.b).a.getPackageName())).hashCode());
        }
        return this.g.intValue();
    }

    public final AbstractC3876k X() {
        if (this.f == null) {
            this.f = new f1(this, this.c.l, 1);
        }
        return this.f;
    }
}

package com.google.android.gms.measurement.internal;

import android.app.job.JobInfo;
import android.app.job.JobScheduler;
import android.content.ComponentName;
import android.os.PersistableBundle;
import com.google.android.gms.ads.nonagon.signalgeneration.AbstractC1642h;

/* loaded from: classes2.dex */
public final class I0 extends AbstractC3888q {
    public JobScheduler d;

    @Override // com.google.android.gms.measurement.internal.AbstractC3888q
    public final boolean U() {
        return true;
    }

    public final int V() {
        Q();
        S();
        Y y = (Y) this.b;
        if (!y.g.f0(null, AbstractC3893t.R0)) {
            return 9;
        }
        if (this.d == null) {
            return 7;
        }
        Boolean boolD0 = y.g.d0("google_analytics_sgtm_upload_enabled");
        if (!(boolD0 == null ? false : boolD0.booleanValue())) {
            return 8;
        }
        if (y.n().k < 119000) {
            return 6;
        }
        if (x1.O0(y.a)) {
            return !y.r().e0() ? 5 : 2;
        }
        return 3;
    }

    public final void W(long j) {
        Q();
        S();
        JobScheduler jobScheduler = this.d;
        Y y = (Y) this.b;
        if (jobScheduler != null && jobScheduler.getPendingJob("measurement-client".concat(String.valueOf(y.a.getPackageName())).hashCode()) != null) {
            I i = y.i;
            Y.k(i);
            i.o.f("[sgtm] There's an existing pending job, skip this schedule.");
            return;
        }
        int iV = V();
        if (iV != 2) {
            I i2 = y.i;
            Y.k(i2);
            i2.o.g("[sgtm] Not eligible for Scion upload", AbstractC1642h.A(iV));
            return;
        }
        I i3 = y.i;
        Y.k(i3);
        i3.o.g("[sgtm] Scheduling Scion upload, millis", Long.valueOf(j));
        PersistableBundle persistableBundle = new PersistableBundle();
        persistableBundle.putString("action", "com.google.android.gms.measurement.SCION_UPLOAD");
        JobInfo jobInfoBuild = new JobInfo.Builder("measurement-client".concat(String.valueOf(y.a.getPackageName())).hashCode(), new ComponentName(y.a, "com.google.android.gms.measurement.AppMeasurementJobService")).setRequiredNetworkType(1).setMinimumLatency(j).setOverrideDeadline(j + j).setExtras(persistableBundle).build();
        JobScheduler jobScheduler2 = this.d;
        com.google.android.gms.common.internal.u.h(jobScheduler2);
        int iSchedule = jobScheduler2.schedule(jobInfoBuild);
        I i4 = y.i;
        Y.k(i4);
        i4.o.g("[sgtm] Scion upload job scheduled with result", iSchedule == 1 ? "SUCCESS" : "FAILURE");
    }
}

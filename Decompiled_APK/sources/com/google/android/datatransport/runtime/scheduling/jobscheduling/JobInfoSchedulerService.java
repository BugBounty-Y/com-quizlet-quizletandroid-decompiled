package com.google.android.datatransport.runtime.scheduling.jobscheduling;

import android.app.job.JobParameters;
import android.app.job.JobService;
import android.util.Base64;
import com.google.android.datatransport.runtime.q;

/* loaded from: classes2.dex */
public class JobInfoSchedulerService extends JobService {
    public static final /* synthetic */ int a = 0;

    @Override // android.app.job.JobService
    public final boolean onStartJob(JobParameters jobParameters) {
        String string = jobParameters.getExtras().getString("backendName");
        String string2 = jobParameters.getExtras().getString("extras");
        int i = jobParameters.getExtras().getInt("priority");
        int i2 = jobParameters.getExtras().getInt("attemptNumber");
        q.b(getApplicationContext());
        com.quizlet.data.repository.set.f fVarA = com.google.android.datatransport.runtime.i.a();
        fVarA.s(string);
        fVarA.d = com.google.android.datatransport.runtime.util.a.b(i);
        if (string2 != null) {
            fVarA.c = Base64.decode(string2, 0);
        }
        i iVar = q.a().d;
        com.google.android.datatransport.runtime.i iVarB = fVarA.b();
        androidx.credentials.playservices.controllers.c cVar = new androidx.credentials.playservices.controllers.c(25, this, jobParameters);
        iVar.getClass();
        iVar.e.execute(new e(i2, 0, iVar, iVarB, cVar));
        return true;
    }

    @Override // android.app.job.JobService
    public final boolean onStopJob(JobParameters jobParameters) {
        return true;
    }
}

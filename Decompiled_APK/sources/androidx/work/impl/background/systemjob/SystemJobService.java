package androidx.work.impl.background.systemjob;

import android.app.Application;
import android.app.job.JobParameters;
import android.app.job.JobService;
import android.os.Build;
import android.os.Looper;
import android.os.PersistableBundle;
import androidx.camera.camera2.internal.RunnableC0130g;
import androidx.camera.core.impl.y0;
import androidx.work.impl.C1433e;
import androidx.work.impl.InterfaceC1430b;
import androidx.work.impl.model.j;
import androidx.work.impl.r;
import androidx.work.z;
import java.util.Arrays;
import java.util.HashMap;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public class SystemJobService extends JobService implements InterfaceC1430b {
    public static final String e = z.e("SystemJobService");
    public r a;
    public final HashMap b = new HashMap();
    public final y0 c = new y0(2);
    public androidx.work.impl.model.c d;

    public static void a(String str) {
        if (Looper.getMainLooper().getThread() != Thread.currentThread()) {
            throw new IllegalStateException(android.support.v4.media.session.a.B("Cannot invoke ", str, " on a background thread"));
        }
    }

    public static j c(JobParameters jobParameters) {
        try {
            PersistableBundle extras = jobParameters.getExtras();
            if (extras == null || !extras.containsKey("EXTRA_WORK_SPEC_ID")) {
                return null;
            }
            return new j(extras.getString("EXTRA_WORK_SPEC_ID"), extras.getInt("EXTRA_WORK_SPEC_GENERATION"));
        } catch (NullPointerException unused) {
            return null;
        }
    }

    @Override // androidx.work.impl.InterfaceC1430b
    public final void b(j jVar, boolean z) {
        a("onExecuted");
        z zVarC = z.c();
        String str = jVar.a;
        zVarC.getClass();
        JobParameters jobParameters = (JobParameters) this.b.remove(jVar);
        this.c.f(jVar);
        if (jobParameters != null) {
            jobFinished(jobParameters, z);
        }
    }

    @Override // android.app.Service
    public final void onCreate() {
        super.onCreate();
        try {
            r rVarH = r.h(getApplicationContext());
            this.a = rVarH;
            C1433e c1433e = rVarH.f;
            this.d = new androidx.work.impl.model.c(c1433e, rVarH.d);
            c1433e.a(this);
        } catch (IllegalStateException e2) {
            if (!Application.class.equals(getApplication().getClass())) {
                throw new IllegalStateException("WorkManager needs to be initialized via a ContentProvider#onCreate() or an Application#onCreate().", e2);
            }
            z.c().f(e, "Could not find WorkManager instance; this may be because an auto-backup is in progress. Ignoring JobScheduler commands for now. Please make sure that you are initializing WorkManager if you have manually disabled WorkManagerInitializer.");
        }
    }

    @Override // android.app.Service
    public final void onDestroy() {
        super.onDestroy();
        r rVar = this.a;
        if (rVar != null) {
            rVar.f.f(this);
        }
    }

    @Override // android.app.job.JobService
    public final boolean onStartJob(JobParameters jobParameters) {
        a("onStartJob");
        if (this.a == null) {
            z.c().getClass();
            jobFinished(jobParameters, true);
            return false;
        }
        j jVarC = c(jobParameters);
        if (jVarC == null) {
            z.c().a(e, "WorkSpec id not found!");
            return false;
        }
        HashMap map = this.b;
        if (map.containsKey(jVarC)) {
            z zVarC = z.c();
            jVarC.toString();
            zVarC.getClass();
            return false;
        }
        z zVarC2 = z.c();
        jVarC.toString();
        zVarC2.getClass();
        map.put(jVarC, jobParameters);
        int i = Build.VERSION.SDK_INT;
        com.google.android.gms.internal.appset.e eVar = new com.google.android.gms.internal.appset.e(4);
        if (jobParameters.getTriggeredContentUris() != null) {
            eVar.c = Arrays.asList(jobParameters.getTriggeredContentUris());
        }
        if (jobParameters.getTriggeredContentAuthorities() != null) {
            eVar.b = Arrays.asList(jobParameters.getTriggeredContentAuthorities());
        }
        if (i >= 28) {
            eVar.d = androidx.arch.core.executor.d.e(jobParameters);
        }
        androidx.work.impl.model.c cVar = this.d;
        androidx.work.impl.j workSpecId = this.c.h(jVarC);
        cVar.getClass();
        Intrinsics.checkNotNullParameter(workSpecId, "workSpecId");
        ((androidx.work.impl.utils.taskexecutor.a) cVar.c).a(new RunnableC0130g(cVar, workSpecId, eVar, 17));
        return true;
    }

    @Override // android.app.job.JobService
    public final boolean onStopJob(JobParameters jobParameters) {
        boolean zContains;
        a("onStopJob");
        if (this.a == null) {
            z.c().getClass();
            return true;
        }
        j jVarC = c(jobParameters);
        if (jVarC == null) {
            z.c().a(e, "WorkSpec id not found!");
            return false;
        }
        z zVarC = z.c();
        jVarC.toString();
        zVarC.getClass();
        this.b.remove(jVarC);
        androidx.work.impl.j workSpecId = this.c.f(jVarC);
        if (workSpecId != null) {
            int iA = Build.VERSION.SDK_INT >= 31 ? e.a(jobParameters) : -512;
            androidx.work.impl.model.c cVar = this.d;
            cVar.getClass();
            Intrinsics.checkNotNullParameter(workSpecId, "workSpecId");
            cVar.z(workSpecId, iA);
        }
        C1433e c1433e = this.a.f;
        String str = jVarC.a;
        synchronized (c1433e.k) {
            zContains = c1433e.i.contains(str);
        }
        return !zContains;
    }
}

package androidx.work.impl.background.systemjob;

import android.app.job.JobInfo;
import android.app.job.JobScheduler;
import android.content.ComponentName;
import android.content.Context;
import android.net.NetworkRequest;
import android.os.Build;
import android.os.PersistableBundle;
import androidx.work.A;
import androidx.work.C1422c;
import androidx.work.C1424e;
import androidx.work.C1425f;
import androidx.work.EnumC1420a;
import androidx.work.J;
import androidx.work.N;
import androidx.work.impl.InterfaceC1435g;
import androidx.work.impl.WorkDatabase;
import androidx.work.impl.WorkDatabase_Impl;
import androidx.work.impl.model.g;
import androidx.work.impl.model.h;
import androidx.work.impl.model.i;
import androidx.work.impl.model.j;
import androidx.work.impl.model.q;
import androidx.work.z;
import com.google.android.gms.internal.mlkit_vision_camera.A2;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import kotlin.collections.C4933y;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class d implements InterfaceC1435g {
    public static final String f = z.e("SystemJobScheduler");
    public final Context a;
    public final JobScheduler b;
    public final c c;
    public final WorkDatabase d;
    public final C1422c e;

    public d(Context context, WorkDatabase workDatabase, C1422c c1422c) {
        JobScheduler jobSchedulerB = a.b(context);
        c cVar = new c(context, c1422c.d, c1422c.l);
        this.a = context;
        this.b = jobSchedulerB;
        this.c = cVar;
        this.d = workDatabase;
        this.e = c1422c;
    }

    public static void b(JobScheduler jobScheduler, int i) {
        try {
            jobScheduler.cancel(i);
        } catch (Throwable th) {
            z.c().b(f, String.format(Locale.getDefault(), "Exception while trying to cancel job (%d)", Integer.valueOf(i)), th);
        }
    }

    public static ArrayList d(Context context, JobScheduler jobScheduler) {
        List<JobInfo> listA = a.a(jobScheduler);
        if (listA == null) {
            return null;
        }
        ArrayList arrayList = new ArrayList(listA.size());
        ComponentName componentName = new ComponentName(context, (Class<?>) SystemJobService.class);
        for (JobInfo jobInfo : listA) {
            if (componentName.equals(jobInfo.getService())) {
                arrayList.add(jobInfo);
            }
        }
        return arrayList;
    }

    public static j f(JobInfo jobInfo) {
        PersistableBundle extras = jobInfo.getExtras();
        if (extras == null) {
            return null;
        }
        try {
            if (!extras.containsKey("EXTRA_WORK_SPEC_ID")) {
                return null;
            }
            return new j(extras.getString("EXTRA_WORK_SPEC_ID"), extras.getInt("EXTRA_WORK_SPEC_GENERATION", 0));
        } catch (NullPointerException unused) {
            return null;
        }
    }

    @Override // androidx.work.impl.InterfaceC1435g
    public final void a(q... qVarArr) {
        int iIntValue;
        C1422c c1422c = this.e;
        WorkDatabase workDatabase = this.d;
        com.google.android.gms.internal.instantapps.a aVar = new com.google.android.gms.internal.instantapps.a(workDatabase);
        for (q qVar : qVarArr) {
            workDatabase.c();
            try {
                q qVarO = workDatabase.u().o(qVar.a);
                String str = f;
                String str2 = qVar.a;
                if (qVarO == null) {
                    z.c().f(str, "Skipping scheduling " + str2 + " because it's no longer in the DB");
                    workDatabase.p();
                } else if (qVarO.b != N.a) {
                    z.c().f(str, "Skipping scheduling " + str2 + " because it is no longer enqueued");
                    workDatabase.p();
                } else {
                    j generationalId = A2.a(qVar);
                    g gVarD = workDatabase.q().d(generationalId);
                    if (gVarD != null) {
                        iIntValue = gVarD.c;
                    } else {
                        c1422c.getClass();
                        Object objN = ((WorkDatabase) aVar.b).n(new androidx.work.impl.utils.e(aVar, c1422c.i, 0));
                        Intrinsics.checkNotNullExpressionValue(objN, "workDatabase.runInTransa…d\n            }\n        )");
                        iIntValue = ((Number) objN).intValue();
                    }
                    if (gVarD == null) {
                        Intrinsics.checkNotNullParameter(generationalId, "generationalId");
                        workDatabase.q().e(new g(generationalId.a, generationalId.b, iIntValue));
                    }
                    g(qVar, iIntValue);
                    workDatabase.p();
                }
            } finally {
                workDatabase.k();
            }
        }
    }

    @Override // androidx.work.impl.InterfaceC1435g
    public final boolean c() {
        return true;
    }

    @Override // androidx.work.impl.InterfaceC1435g
    public final void e(String str) {
        ArrayList arrayList;
        Context context = this.a;
        JobScheduler jobScheduler = this.b;
        ArrayList arrayListD = d(context, jobScheduler);
        if (arrayListD == null) {
            arrayList = null;
        } else {
            ArrayList arrayList2 = new ArrayList(2);
            Iterator it2 = arrayListD.iterator();
            while (it2.hasNext()) {
                JobInfo jobInfo = (JobInfo) it2.next();
                j jVarF = f(jobInfo);
                if (jVarF != null && str.equals(jVarF.a)) {
                    arrayList2.add(Integer.valueOf(jobInfo.getId()));
                }
            }
            arrayList = arrayList2;
        }
        if (arrayList == null || arrayList.isEmpty()) {
            return;
        }
        Iterator it3 = arrayList.iterator();
        while (it3.hasNext()) {
            b(jobScheduler, ((Integer) it3.next()).intValue());
        }
        i iVarQ = this.d.q();
        WorkDatabase_Impl workDatabase_Impl = (WorkDatabase_Impl) iVarQ.b;
        workDatabase_Impl.b();
        h hVar = (h) iVarQ.e;
        androidx.sqlite.db.framework.i iVarA = hVar.a();
        iVarA.g(1, str);
        try {
            workDatabase_Impl.c();
            try {
                iVarA.a();
                workDatabase_Impl.p();
            } finally {
                workDatabase_Impl.k();
            }
        } finally {
            hVar.n(iVarA);
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    public final void g(q qVar, int i) {
        int i2;
        long j;
        String str;
        String str2 = f;
        c cVar = this.c;
        cVar.getClass();
        C1425f c1425f = qVar.j;
        PersistableBundle persistableBundle = new PersistableBundle();
        String str3 = qVar.a;
        persistableBundle.putString("EXTRA_WORK_SPEC_ID", str3);
        persistableBundle.putInt("EXTRA_WORK_SPEC_GENERATION", qVar.t);
        persistableBundle.putBoolean("EXTRA_IS_PERIODIC", qVar.c());
        JobInfo.Builder requiresCharging = new JobInfo.Builder(i, cVar.a).setRequiresCharging(c1425f.c);
        boolean z = c1425f.d;
        JobInfo.Builder builder = requiresCharging.setRequiresDeviceIdle(z).setExtras(persistableBundle);
        NetworkRequest networkRequest = c1425f.b.a;
        int i3 = Build.VERSION.SDK_INT;
        if (i3 < 28 || networkRequest == null) {
            A a = c1425f.a;
            if (i3 < 30 || a != A.f) {
                int iOrdinal = a.ordinal();
                if (iOrdinal == 0) {
                    i2 = 0;
                } else if (iOrdinal != 1) {
                    i2 = 2;
                    if (iOrdinal != 2) {
                        i2 = 3;
                        if (iOrdinal != 3) {
                            i2 = 4;
                            if (iOrdinal != 4) {
                                z zVarC = z.c();
                                a.toString();
                                zVarC.getClass();
                                i2 = 1;
                            }
                        }
                    }
                } else {
                    i2 = 1;
                }
                builder.setRequiredNetworkType(i2);
            } else {
                builder.setRequiredNetwork(new NetworkRequest.Builder().addCapability(25).build());
            }
        } else {
            Intrinsics.checkNotNullParameter(builder, "builder");
            builder.setRequiredNetwork(networkRequest);
        }
        if (!z) {
            builder.setBackoffCriteria(qVar.m, qVar.l == EnumC1420a.b ? 0 : 1);
        }
        long jA = qVar.a();
        cVar.b.getClass();
        long jMax = Math.max(jA - System.currentTimeMillis(), 0L);
        if (i3 <= 28 || jMax > 0) {
            builder.setMinimumLatency(jMax);
        } else if (!qVar.q && cVar.c) {
            builder.setImportantWhileForeground(true);
        }
        if (c1425f.a()) {
            for (C1424e c1424e : c1425f.i) {
                builder.addTriggerContentUri(new JobInfo.TriggerContentUri(c1424e.a, c1424e.b ? 1 : 0));
            }
            j = 0;
            builder.setTriggerContentUpdateDelay(c1425f.g);
            builder.setTriggerContentMaxDelay(c1425f.h);
        } else {
            j = 0;
        }
        builder.setPersisted(false);
        int i4 = Build.VERSION.SDK_INT;
        builder.setRequiresBatteryNotLow(c1425f.e);
        builder.setRequiresStorageNotLow(c1425f.f);
        Object[] objArr = qVar.k > 0;
        boolean z2 = jMax > j;
        if (i4 >= 31 && qVar.q && objArr == false && !z2) {
            builder.setExpedited(true);
        }
        if (i4 >= 35 && (str = qVar.x) != null) {
            builder.setTraceTag(str);
        }
        JobInfo jobInfoBuild = builder.build();
        z.c().getClass();
        try {
            if (this.b.schedule(jobInfoBuild) == 0) {
                z.c().f(str2, "Unable to schedule work ID " + str3);
                if (qVar.q && qVar.r == J.a) {
                    qVar.q = false;
                    z.c().getClass();
                    g(qVar, i);
                }
            }
        } catch (IllegalStateException e) {
            String str4 = a.a;
            Context context = this.a;
            Intrinsics.checkNotNullParameter(context, "context");
            WorkDatabase workDatabase = this.d;
            Intrinsics.checkNotNullParameter(workDatabase, "workDatabase");
            C1422c configuration = this.e;
            Intrinsics.checkNotNullParameter(configuration, "configuration");
            int i5 = Build.VERSION.SDK_INT;
            int i6 = i5 >= 31 ? 150 : 100;
            int size = workDatabase.u().m().size();
            String strS = "<faulty JobScheduler failed to getPendingJobs>";
            if (i5 >= 34) {
                JobScheduler jobSchedulerB = a.b(context);
                List listA = a.a(jobSchedulerB);
                if (listA != null) {
                    ArrayList arrayListD = d(context, jobSchedulerB);
                    int size2 = arrayListD != null ? listA.size() - arrayListD.size() : 0;
                    String str5 = size2 == 0 ? null : size2 + " of which are not owned by WorkManager";
                    Object systemService = context.getSystemService("jobscheduler");
                    Intrinsics.e(systemService, "null cannot be cast to non-null type android.app.job.JobScheduler");
                    ArrayList arrayListD2 = d(context, (JobScheduler) systemService);
                    int size3 = arrayListD2 != null ? arrayListD2.size() : 0;
                    String[] elements = {listA.size() + " jobs in \"androidx.work.systemjobscheduler\" namespace", str5, size3 != 0 ? size3 + " from WorkManager in the default namespace" : null};
                    Intrinsics.checkNotNullParameter(elements, "elements");
                    strS = CollectionsKt.S(C4933y.z(elements), ",\n", null, null, null, 62);
                }
            } else {
                ArrayList arrayListD3 = d(context, a.b(context));
                if (arrayListD3 != null) {
                    strS = arrayListD3.size() + " jobs from WorkManager";
                }
            }
            StringBuilder sb = new StringBuilder("JobScheduler ");
            sb.append(i6);
            sb.append(" job limit exceeded.\nIn JobScheduler there are ");
            sb.append(strS);
            sb.append(".\nThere are ");
            sb.append(size);
            sb.append(" jobs tracked by WorkManager's database;\nthe Configuration limit is ");
            String strQ = android.support.v4.media.session.a.q(sb, configuration.k, '.');
            z.c().a(str2, strQ);
            throw new IllegalStateException(strQ, e);
        } catch (Throwable th) {
            z.c().b(str2, "Unable to schedule " + qVar, th);
        }
    }
}

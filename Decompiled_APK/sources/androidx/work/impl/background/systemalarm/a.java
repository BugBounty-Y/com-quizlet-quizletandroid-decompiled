package androidx.work.impl.background.systemalarm;

import android.app.AlarmManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import androidx.work.impl.WorkDatabase;
import androidx.work.impl.model.i;
import androidx.work.impl.model.j;
import androidx.work.z;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class a {
    public static final /* synthetic */ int a = 0;

    static {
        z.e("Alarms");
    }

    public static void a(Context context, j jVar, int i) {
        AlarmManager alarmManager = (AlarmManager) context.getSystemService("alarm");
        String str = b.f;
        Intent intent = new Intent(context, (Class<?>) SystemAlarmService.class);
        intent.setAction("ACTION_DELAY_MET");
        b.d(intent, jVar);
        PendingIntent service = PendingIntent.getService(context, i, intent, 603979776);
        if (service == null || alarmManager == null) {
            return;
        }
        z zVarC = z.c();
        jVar.toString();
        zVarC.getClass();
        alarmManager.cancel(service);
    }

    public static void b(Context context, WorkDatabase workDatabase, j generationalId, long j) {
        i iVarQ = workDatabase.q();
        androidx.work.impl.model.g gVarD = iVarQ.d(generationalId);
        int i = 0;
        if (gVarD != null) {
            int i2 = gVarD.c;
            a(context, generationalId, i2);
            AlarmManager alarmManager = (AlarmManager) context.getSystemService("alarm");
            String str = b.f;
            Intent intent = new Intent(context, (Class<?>) SystemAlarmService.class);
            intent.setAction("ACTION_DELAY_MET");
            b.d(intent, generationalId);
            PendingIntent service = PendingIntent.getService(context, i2, intent, 201326592);
            if (alarmManager != null) {
                alarmManager.setExact(0, j, service);
                return;
            }
            return;
        }
        Object objN = workDatabase.n(new androidx.work.impl.utils.d(new com.google.android.gms.internal.instantapps.a(workDatabase), i));
        Intrinsics.checkNotNullExpressionValue(objN, "workDatabase.runInTransa…NAGER_ID_KEY) }\n        )");
        int iIntValue = ((Number) objN).intValue();
        Intrinsics.checkNotNullParameter(generationalId, "generationalId");
        iVarQ.e(new androidx.work.impl.model.g(generationalId.a, generationalId.b, iIntValue));
        AlarmManager alarmManager2 = (AlarmManager) context.getSystemService("alarm");
        String str2 = b.f;
        Intent intent2 = new Intent(context, (Class<?>) SystemAlarmService.class);
        intent2.setAction("ACTION_DELAY_MET");
        b.d(intent2, generationalId);
        PendingIntent service2 = PendingIntent.getService(context, iIntValue, intent2, 201326592);
        if (alarmManager2 != null) {
            alarmManager2.setExact(0, j, service2);
        }
    }
}

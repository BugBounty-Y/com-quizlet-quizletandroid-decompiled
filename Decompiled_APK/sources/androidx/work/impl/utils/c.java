package androidx.work.impl.utils;

import android.app.AlarmManager;
import android.app.PendingIntent;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.database.sqlite.SQLiteAccessPermException;
import android.database.sqlite.SQLiteCantOpenDatabaseException;
import android.database.sqlite.SQLiteConstraintException;
import android.database.sqlite.SQLiteDatabaseCorruptException;
import android.database.sqlite.SQLiteDatabaseLockedException;
import android.database.sqlite.SQLiteDiskIOException;
import android.database.sqlite.SQLiteException;
import android.database.sqlite.SQLiteFullException;
import android.database.sqlite.SQLiteTableLockedException;
import android.os.Build;
import android.text.TextUtils;
import androidx.work.C1422c;
import androidx.work.z;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3233p6;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3410x2;
import java.util.concurrent.TimeUnit;

/* loaded from: classes.dex */
public final class c implements Runnable {
    public static final String e = z.e("ForceStopRunnable");
    public static final long f = TimeUnit.DAYS.toMillis(3650);
    public final Context a;
    public final androidx.work.impl.r b;
    public final com.google.firebase.platforminfo.c c;
    public int d = 0;

    public c(Context context, androidx.work.impl.r rVar) {
        this.a = context.getApplicationContext();
        this.b = rVar;
        this.c = rVar.g;
    }

    public static void b(Context context) {
        AlarmManager alarmManager = (AlarmManager) context.getSystemService("alarm");
        int i = Build.VERSION.SDK_INT >= 31 ? 167772160 : 134217728;
        Intent intent = new Intent();
        intent.setComponent(new ComponentName(context, (Class<?>) ForceStopRunnable$BroadcastReceiver.class));
        intent.setAction("ACTION_FORCE_STOP_RESCHEDULE");
        PendingIntent broadcast = PendingIntent.getBroadcast(context, -1, intent, i);
        long jCurrentTimeMillis = System.currentTimeMillis() + f;
        if (alarmManager != null) {
            alarmManager.setExact(0, jCurrentTimeMillis, broadcast);
        }
    }

    /* JADX WARN: Finally extract failed */
    /* JADX WARN: Removed duplicated region for block: B:102:0x020a  */
    /* JADX WARN: Removed duplicated region for block: B:106:0x0224  */
    /* JADX WARN: Removed duplicated region for block: B:145:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void a() {
        /*
            Method dump skipped, instructions count: 621
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.work.impl.utils.c.a():void");
    }

    @Override // java.lang.Runnable
    public final void run() {
        boolean zA;
        String str = e;
        androidx.work.impl.r rVar = this.b;
        try {
            C1422c c1422c = rVar.b;
            c1422c.getClass();
            boolean zIsEmpty = TextUtils.isEmpty(null);
            Context context = this.a;
            if (zIsEmpty) {
                z.c().getClass();
                zA = true;
            } else {
                zA = i.a(context, c1422c);
                z.c().getClass();
            }
            if (!zA) {
                return;
            }
            while (true) {
                try {
                    AbstractC3410x2.a(context);
                    z.c().getClass();
                    try {
                        a();
                        return;
                    } catch (SQLiteAccessPermException | SQLiteCantOpenDatabaseException | SQLiteConstraintException | SQLiteDatabaseCorruptException | SQLiteDatabaseLockedException | SQLiteDiskIOException | SQLiteFullException | SQLiteTableLockedException e2) {
                        int i = this.d + 1;
                        this.d = i;
                        if (i >= 3) {
                            String str2 = AbstractC3233p6.b(context) ? "The file system on the device is in a bad state. WorkManager cannot access the app's internal data store." : "WorkManager can't be accessed from direct boot, because credential encrypted storage isn't accessible.\nDon't access or initialise WorkManager from directAware components. See https://developer.android.com/training/articles/direct-boot";
                            z.c().b(str, str2, e2);
                            IllegalStateException illegalStateException = new IllegalStateException(str2, e2);
                            rVar.b.getClass();
                            throw illegalStateException;
                        }
                        z.c().getClass();
                        try {
                            Thread.sleep(this.d * 300);
                        } catch (InterruptedException unused) {
                        }
                    }
                } catch (SQLiteException e3) {
                    z.c().a(str, "Unexpected SQLite exception during migrations");
                    IllegalStateException illegalStateException2 = new IllegalStateException("Unexpected SQLite exception during migrations", e3);
                    rVar.b.getClass();
                    throw illegalStateException2;
                }
            }
        } finally {
            rVar.j();
        }
    }
}

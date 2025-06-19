package androidx.work.impl.background.systemalarm;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import androidx.work.impl.r;
import androidx.work.z;
import java.util.Objects;

/* loaded from: classes.dex */
public class RescheduleReceiver extends BroadcastReceiver {
    public static final String a = z.e("RescheduleReceiver");

    @Override // android.content.BroadcastReceiver
    public final void onReceive(Context context, Intent intent) {
        z zVarC = z.c();
        Objects.toString(intent);
        zVarC.getClass();
        try {
            r rVarH = r.h(context);
            BroadcastReceiver.PendingResult pendingResultGoAsync = goAsync();
            rVarH.getClass();
            synchronized (r.m) {
                try {
                    BroadcastReceiver.PendingResult pendingResult = rVarH.i;
                    if (pendingResult != null) {
                        pendingResult.finish();
                    }
                    rVarH.i = pendingResultGoAsync;
                    if (rVarH.h) {
                        pendingResultGoAsync.finish();
                        rVarH.i = null;
                    }
                } finally {
                }
            }
        } catch (IllegalStateException e) {
            z.c().b(a, "Cannot reschedule jobs. WorkManager needs to be initialized via a ContentProvider#onCreate() or an Application#onCreate().", e);
        }
    }
}

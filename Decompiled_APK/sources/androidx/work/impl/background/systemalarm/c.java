package androidx.work.impl.background.systemalarm;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import androidx.work.z;
import java.util.Objects;

/* loaded from: classes.dex */
public abstract class c extends BroadcastReceiver {
    public static final /* synthetic */ int a = 0;

    static {
        z.e("ConstraintProxy");
    }

    @Override // android.content.BroadcastReceiver
    public final void onReceive(Context context, Intent intent) {
        z zVarC = z.c();
        Objects.toString(intent);
        zVarC.getClass();
        String str = b.f;
        Intent intent2 = new Intent(context, (Class<?>) SystemAlarmService.class);
        intent2.setAction("ACTION_CONSTRAINTS_CHANGED");
        context.startService(intent2);
    }
}

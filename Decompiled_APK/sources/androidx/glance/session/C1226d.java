package androidx.glance.session;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.Build;
import android.os.PowerManager;
import java.util.Iterator;
import java.util.List;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.glance.session.d, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1226d extends BroadcastReceiver {
    public static final List b;
    public static final IntentFilter c;
    public final androidx.credentials.playservices.controllers.BeginSignIn.d a;

    static {
        List listJ = kotlin.collections.B.j("android.os.action.DEVICE_IDLE_MODE_CHANGED", "android.os.action.LIGHT_DEVICE_IDLE_MODE_CHANGED", "android.os.action.LOW_POWER_STANDBY_ENABLED_CHANGED");
        b = listJ;
        IntentFilter intentFilter = new IntentFilter();
        Iterator it2 = listJ.iterator();
        while (it2.hasNext()) {
            intentFilter.addAction((String) it2.next());
        }
        c = intentFilter;
    }

    public C1226d(androidx.credentials.playservices.controllers.BeginSignIn.d dVar) {
        this.a = dVar;
    }

    public final void a(Context context) {
        int i = Build.VERSION.SDK_INT;
        Object systemService = context.getSystemService("power");
        Intrinsics.e(systemService, "null cannot be cast to non-null type android.os.PowerManager");
        PowerManager powerManager = (PowerManager) systemService;
        boolean zA = C1223a.a.a(powerManager);
        if (i >= 33) {
            zA = zA || C1224b.a.a(powerManager);
        }
        if (zA) {
            this.a.invoke();
        }
    }

    @Override // android.content.BroadcastReceiver
    public final void onReceive(Context context, Intent intent) {
        if (CollectionsKt.F(b, intent.getAction())) {
            a(context);
        }
    }
}

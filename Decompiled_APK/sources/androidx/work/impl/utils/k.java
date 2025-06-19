package androidx.work.impl.utils;

import android.content.Context;
import android.os.PowerManager;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.work.z;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class k {
    public static final String a;

    static {
        String strE = z.e("WakeLocks");
        Intrinsics.checkNotNullExpressionValue(strE, "tagWithPrefix(\"WakeLocks\")");
        a = strE;
    }

    public static final PowerManager.WakeLock a(Context context, String tag) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(tag, "tag");
        Object systemService = context.getApplicationContext().getSystemService("power");
        Intrinsics.e(systemService, "null cannot be cast to non-null type android.os.PowerManager");
        String strD = AbstractC0147y.d("WorkManager: ", tag);
        PowerManager.WakeLock wakeLock = ((PowerManager) systemService).newWakeLock(1, strD);
        synchronized (l.a) {
        }
        Intrinsics.checkNotNullExpressionValue(wakeLock, "wakeLock");
        return wakeLock;
    }
}

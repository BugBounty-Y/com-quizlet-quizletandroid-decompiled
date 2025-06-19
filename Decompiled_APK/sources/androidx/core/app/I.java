package androidx.core.app;

import android.app.NotificationManager;

/* loaded from: classes.dex */
public abstract class I {
    public static boolean a(NotificationManager notificationManager) {
        return notificationManager.canUseFullScreenIntent();
    }
}

package androidx.core.app;

import android.app.NotificationChannel;
import android.app.NotificationManager;

/* renamed from: androidx.core.app.l, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractC1025l {
    public static String a(NotificationChannel notificationChannel) {
        return notificationChannel.getConversationId();
    }

    public static NotificationChannel b(NotificationManager notificationManager, String str, String str2) {
        return notificationManager.getNotificationChannel(str, str2);
    }

    public static String c(NotificationChannel notificationChannel) {
        return notificationChannel.getParentChannelId();
    }

    public static String d(NotificationChannel notificationChannel) {
        return notificationChannel.getParentChannelId();
    }

    public static void e(NotificationChannel notificationChannel) {
        notificationChannel.isImportantConversation();
    }

    public static void f(NotificationChannel notificationChannel, String str, String str2) {
        notificationChannel.setConversationId(str, str2);
    }
}

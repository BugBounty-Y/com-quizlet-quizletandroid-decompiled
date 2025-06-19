package androidx.core.app;

import android.app.Notification;

/* loaded from: classes.dex */
public abstract class z {
    public static Notification.MessagingStyle a(Notification.MessagingStyle messagingStyle, Notification.MessagingStyle.Message message) {
        return messagingStyle.addHistoricMessage(message);
    }
}

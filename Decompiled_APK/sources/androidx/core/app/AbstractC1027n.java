package androidx.core.app;

import android.app.Notification;
import android.app.NotificationChannelGroup;
import android.app.NotificationManager;
import android.app.Person;

/* renamed from: androidx.core.app.n, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractC1027n {
    public static void a(Notification.Builder builder, Person person) {
        builder.addPerson(person);
    }

    public static String b(NotificationChannelGroup notificationChannelGroup) {
        return notificationChannelGroup.getDescription();
    }

    public static NotificationChannelGroup c(NotificationManager notificationManager, String str) {
        return notificationManager.getNotificationChannelGroup(str);
    }

    public static void d(NotificationChannelGroup notificationChannelGroup) {
        notificationChannelGroup.isBlocked();
    }

    public static void e(NotificationChannelGroup notificationChannelGroup, String str) {
        notificationChannelGroup.setDescription(str);
    }

    public static void f(Notification.Action.Builder builder) {
        builder.setSemanticAction(0);
    }

    public static Person g(Q q) {
        return new Person.Builder().setName(q.a).setIcon(null).setUri(q.b).setKey(q.c).setBot(q.d).setImportant(q.e).build();
    }
}

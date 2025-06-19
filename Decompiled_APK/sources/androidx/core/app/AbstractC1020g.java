package androidx.core.app;

import android.app.Notification;
import android.app.NotificationChannel;
import android.content.Context;
import com.quizlet.features.flashcards.autoplay.FlashcardsAutoplayService;

/* renamed from: androidx.core.app.g, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractC1020g {
    public static void a(NotificationChannel notificationChannel) {
        notificationChannel.canBubble();
    }

    public static String b(Context context) {
        return context.getOpPackageName();
    }

    public static void c(Notification.Builder builder, boolean z) {
        builder.setAllowSystemGeneratedContextualActions(z);
    }

    public static void d(Notification.Builder builder) {
        builder.setBubbleMetadata(null);
    }

    public static void e(Notification.Action.Builder builder) {
        builder.setContextual(false);
    }

    public static void f(FlashcardsAutoplayService flashcardsAutoplayService, Notification notification) {
        flashcardsAutoplayService.startForeground(1, notification, 2);
    }

    public static void g(FlashcardsAutoplayService flashcardsAutoplayService, Notification notification) {
        flashcardsAutoplayService.startForeground(1, notification, 2);
    }
}

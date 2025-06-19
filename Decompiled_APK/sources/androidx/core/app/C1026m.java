package androidx.core.app;

import android.app.Notification;
import android.app.NotificationChannel;
import android.media.AudioAttributes;
import android.net.Uri;
import android.os.Build;
import android.provider.Settings;

/* renamed from: androidx.core.app.m, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1026m {
    public final String a;
    public final CharSequence b;
    public final int c;
    public final String d;
    public final String e;
    public final boolean f;
    public final Uri g;
    public final AudioAttributes h;
    public final boolean i;
    public final int j;
    public final boolean k;
    public final long[] l;
    public final String m;
    public final String n;

    public C1026m(NotificationChannel notificationChannel) {
        String id = notificationChannel.getId();
        int importance = notificationChannel.getImportance();
        this.f = true;
        this.g = Settings.System.DEFAULT_NOTIFICATION_URI;
        this.j = 0;
        id.getClass();
        this.a = id;
        this.c = importance;
        this.h = Notification.AUDIO_ATTRIBUTES_DEFAULT;
        this.b = notificationChannel.getName();
        this.d = notificationChannel.getDescription();
        this.e = notificationChannel.getGroup();
        this.f = notificationChannel.canShowBadge();
        this.g = notificationChannel.getSound();
        this.h = notificationChannel.getAudioAttributes();
        this.i = notificationChannel.shouldShowLights();
        this.j = notificationChannel.getLightColor();
        this.k = notificationChannel.shouldVibrate();
        this.l = notificationChannel.getVibrationPattern();
        int i = Build.VERSION.SDK_INT;
        if (i >= 30) {
            this.m = AbstractC1025l.c(notificationChannel);
            this.n = AbstractC1025l.a(notificationChannel);
        }
        notificationChannel.canBypassDnd();
        notificationChannel.getLockscreenVisibility();
        if (i >= 29) {
            AbstractC1020g.a(notificationChannel);
        }
        if (i >= 30) {
            AbstractC1025l.e(notificationChannel);
        }
    }

    public final NotificationChannel a() {
        String str;
        String str2;
        int i = Build.VERSION.SDK_INT;
        NotificationChannel notificationChannel = new NotificationChannel(this.a, this.b, this.c);
        notificationChannel.setDescription(this.d);
        notificationChannel.setGroup(this.e);
        notificationChannel.setShowBadge(this.f);
        notificationChannel.setSound(this.g, this.h);
        notificationChannel.enableLights(this.i);
        notificationChannel.setLightColor(this.j);
        notificationChannel.setVibrationPattern(this.l);
        notificationChannel.enableVibration(this.k);
        if (i >= 30 && (str = this.m) != null && (str2 = this.n) != null) {
            AbstractC1025l.f(notificationChannel, str, str2);
        }
        return notificationChannel;
    }
}

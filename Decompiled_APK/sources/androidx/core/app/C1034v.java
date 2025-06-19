package androidx.core.app;

import android.app.Notification;
import android.app.PendingIntent;
import android.content.Context;
import android.content.res.Resources;
import android.graphics.Bitmap;
import android.graphics.PorterDuff;
import android.os.Build;
import android.os.Bundle;
import android.widget.RemoteViews;
import androidx.core.graphics.drawable.IconCompat;
import com.quizlet.quizletandroid.R;
import java.util.ArrayList;

/* renamed from: androidx.core.app.v, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public class C1034v {
    public final Context a;
    public final ArrayList b;
    public final ArrayList c;
    public final ArrayList d;
    public CharSequence e;
    public CharSequence f;
    public PendingIntent g;
    public IconCompat h;
    public int i;
    public int j;
    public boolean k;
    public F l;
    public CharSequence m;
    public boolean n;
    public String o;
    public Bundle p;
    public int q;
    public int r;
    public Notification s;
    public RemoteViews t;
    public RemoteViews u;
    public String v;
    public String w;
    public final boolean x;
    public final Notification y;
    public final ArrayList z;

    public C1034v(Context context, String str) {
        this.b = new ArrayList();
        this.c = new ArrayList();
        this.d = new ArrayList();
        this.k = true;
        this.n = false;
        this.q = 0;
        this.r = 0;
        Notification notification = new Notification();
        this.y = notification;
        this.a = context;
        this.v = str;
        notification.when = System.currentTimeMillis();
        notification.audioStreamType = -1;
        this.j = 0;
        this.z = new ArrayList();
        this.x = true;
    }

    public static CharSequence b(CharSequence charSequence) {
        return (charSequence != null && charSequence.length() > 5120) ? charSequence.subSequence(0, 5120) : charSequence;
    }

    public final Notification a() {
        Bundle bundle;
        RemoteViews remoteViewsMakeHeadsUpContentView;
        RemoteViews remoteViewsMakeBigContentView;
        H h = new H(this);
        C1034v c1034v = h.c;
        F f = c1034v.l;
        if (f != null) {
            f.apply(h);
        }
        RemoteViews remoteViewsMakeContentView = f != null ? f.makeContentView(h) : null;
        Notification notificationBuild = h.b.build();
        if (remoteViewsMakeContentView != null) {
            notificationBuild.contentView = remoteViewsMakeContentView;
        } else {
            RemoteViews remoteViews = c1034v.t;
            if (remoteViews != null) {
                notificationBuild.contentView = remoteViews;
            }
        }
        if (f != null && (remoteViewsMakeBigContentView = f.makeBigContentView(h)) != null) {
            notificationBuild.bigContentView = remoteViewsMakeBigContentView;
        }
        if (f != null && (remoteViewsMakeHeadsUpContentView = c1034v.l.makeHeadsUpContentView(h)) != null) {
            notificationBuild.headsUpContentView = remoteViewsMakeHeadsUpContentView;
        }
        if (f != null && (bundle = notificationBuild.extras) != null) {
            f.addCompatExtras(bundle);
        }
        return notificationBuild;
    }

    public final void c(int i, boolean z) {
        Notification notification = this.y;
        if (z) {
            notification.flags = i | notification.flags;
        } else {
            notification.flags = (~i) & notification.flags;
        }
    }

    public final void d(Bitmap bitmap) {
        IconCompat iconCompat;
        if (bitmap == null) {
            iconCompat = null;
        } else {
            if (Build.VERSION.SDK_INT < 27) {
                Resources resources = this.a.getResources();
                int dimensionPixelSize = resources.getDimensionPixelSize(R.dimen.compat_notification_large_icon_max_width);
                int dimensionPixelSize2 = resources.getDimensionPixelSize(R.dimen.compat_notification_large_icon_max_height);
                if (bitmap.getWidth() > dimensionPixelSize || bitmap.getHeight() > dimensionPixelSize2) {
                    double dMin = Math.min(dimensionPixelSize / Math.max(1, bitmap.getWidth()), dimensionPixelSize2 / Math.max(1, bitmap.getHeight()));
                    bitmap = Bitmap.createScaledBitmap(bitmap, (int) Math.ceil(bitmap.getWidth() * dMin), (int) Math.ceil(bitmap.getHeight() * dMin), true);
                }
            }
            PorterDuff.Mode mode = IconCompat.k;
            bitmap.getClass();
            IconCompat iconCompat2 = new IconCompat(1);
            iconCompat2.b = bitmap;
            iconCompat = iconCompat2;
        }
        this.h = iconCompat;
    }

    public final void e(F f) {
        if (this.l != f) {
            this.l = f;
            if (f != null) {
                f.setBuilder(this);
            }
        }
    }

    @Deprecated
    public C1034v(Context context) {
        this(context, null);
    }
}

package com.google.android.gms.common;

import android.R;
import android.app.Activity;
import android.app.AlertDialog;
import android.app.FragmentManager;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.DialogInterface;
import android.content.pm.PackageManager;
import android.content.res.Resources;
import android.os.Bundle;
import android.util.Log;
import android.util.TypedValue;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.core.app.C1029p;
import androidx.core.app.C1032t;
import androidx.core.app.C1034v;
import androidx.core.graphics.drawable.IconCompat;
import androidx.fragment.app.AbstractC1136h0;
import androidx.fragment.app.I;
import com.google.android.gms.common.api.GoogleApiActivity;
import com.google.android.gms.common.api.internal.InterfaceC1649g;
import com.google.android.gms.common.internal.u;

/* loaded from: classes2.dex */
public class GoogleApiAvailability extends c {
    public static final Object c = new Object();
    public static final GoogleApiAvailability d = new GoogleApiAvailability();

    public static AlertDialog e(Activity activity, int i, com.google.android.gms.common.internal.o oVar, DialogInterface.OnCancelListener onCancelListener) {
        if (i == 0) {
            return null;
        }
        TypedValue typedValue = new TypedValue();
        activity.getTheme().resolveAttribute(R.attr.alertDialogTheme, typedValue, true);
        AlertDialog.Builder builder = "Theme.Dialog.Alert".equals(activity.getResources().getResourceEntryName(typedValue.resourceId)) ? new AlertDialog.Builder(activity, 5) : null;
        if (builder == null) {
            builder = new AlertDialog.Builder(activity);
        }
        builder.setMessage(com.google.android.gms.common.internal.l.b(activity, i));
        if (onCancelListener != null) {
            builder.setOnCancelListener(onCancelListener);
        }
        Resources resources = activity.getResources();
        String string = i != 1 ? i != 2 ? i != 3 ? resources.getString(R.string.ok) : resources.getString(com.quizlet.quizletandroid.R.string.common_google_play_services_enable_button) : resources.getString(com.quizlet.quizletandroid.R.string.common_google_play_services_update_button) : resources.getString(com.quizlet.quizletandroid.R.string.common_google_play_services_install_button);
        if (string != null) {
            if (oVar == null) {
                oVar = null;
            }
            builder.setPositiveButton(string, oVar);
        }
        String strA = com.google.android.gms.common.internal.l.a(activity, i);
        if (strA != null) {
            builder.setTitle(strA);
        }
        Log.w("GoogleApiAvailability", android.support.v4.media.session.a.f(i, "Creating dialog for Google Play services availability issue. ConnectionResult="), new IllegalArgumentException());
        return builder.create();
    }

    public static void h(Activity activity, AlertDialog alertDialog, String str, DialogInterface.OnCancelListener onCancelListener) {
        try {
            if (activity instanceof I) {
                AbstractC1136h0 supportFragmentManager = ((I) activity).getSupportFragmentManager();
                f fVar = new f();
                u.i(alertDialog, "Cannot display null dialog");
                alertDialog.setOnCancelListener(null);
                alertDialog.setOnDismissListener(null);
                fVar.q = alertDialog;
                if (onCancelListener != null) {
                    fVar.r = onCancelListener;
                }
                fVar.O(supportFragmentManager, str);
                return;
            }
        } catch (NoClassDefFoundError unused) {
        }
        FragmentManager fragmentManager = activity.getFragmentManager();
        b bVar = new b();
        u.i(alertDialog, "Cannot display null dialog");
        alertDialog.setOnCancelListener(null);
        alertDialog.setOnDismissListener(null);
        bVar.a = alertDialog;
        if (onCancelListener != null) {
            bVar.b = onCancelListener;
        }
        bVar.show(fragmentManager, str);
    }

    public final AlertDialog d(Activity activity, int i, int i2, GoogleApiActivity googleApiActivity) {
        return e(activity, i, com.google.android.gms.common.internal.o.b(activity, super.b(activity, "d", i), i2), googleApiActivity);
    }

    public final void f(Activity activity, InterfaceC1649g interfaceC1649g, int i, DialogInterface.OnCancelListener onCancelListener) {
        AlertDialog alertDialogE = e(activity, i, com.google.android.gms.common.internal.o.c(interfaceC1649g, super.b(activity, "d", i), 2), onCancelListener);
        if (alertDialogE == null) {
            return;
        }
        h(activity, alertDialogE, "GooglePlayServicesErrorDialog", onCancelListener);
    }

    public final void g(Context context, int i, PendingIntent pendingIntent) throws Resources.NotFoundException {
        int i2;
        Log.w("GoogleApiAvailability", AbstractC0147y.c(i, "GMS core API Availability. ConnectionResult=", ", tag=null"), new IllegalArgumentException());
        if (i == 18) {
            new g(this, context).sendEmptyMessageDelayed(1, 120000L);
            return;
        }
        if (pendingIntent == null) {
            if (i == 6) {
                Log.w("GoogleApiAvailability", "Missing resolution for ConnectionResult.RESOLUTION_REQUIRED. Call GoogleApiAvailability#showErrorNotification(Context, ConnectionResult) instead.");
                return;
            }
            return;
        }
        String strE = i == 6 ? com.google.android.gms.common.internal.l.e(context, "common_google_play_services_resolution_required_title") : com.google.android.gms.common.internal.l.a(context, i);
        if (strE == null) {
            strE = context.getResources().getString(com.quizlet.quizletandroid.R.string.common_google_play_services_notification_ticker);
        }
        String strD = (i == 6 || i == 19) ? com.google.android.gms.common.internal.l.d(context, "common_google_play_services_resolution_required_text", com.google.android.gms.common.internal.l.c(context)) : com.google.android.gms.common.internal.l.b(context, i);
        Resources resources = context.getResources();
        Object systemService = context.getSystemService("notification");
        u.h(systemService);
        NotificationManager notificationManager = (NotificationManager) systemService;
        C1034v c1034v = new C1034v(context);
        c1034v.n = true;
        c1034v.c(16, true);
        c1034v.e = C1034v.b(strE);
        C1032t c1032t = new C1032t();
        c1032t.a = C1034v.b(strD);
        c1034v.e(c1032t);
        PackageManager packageManager = context.getPackageManager();
        if (com.google.android.gms.common.util.c.c == null) {
            com.google.android.gms.common.util.c.c = Boolean.valueOf(packageManager.hasSystemFeature("android.hardware.type.watch"));
        }
        boolean zBooleanValue = com.google.android.gms.common.util.c.c.booleanValue();
        int i3 = R.drawable.stat_sys_warning;
        if (zBooleanValue) {
            int i4 = context.getApplicationInfo().icon;
            if (i4 != 0) {
                i3 = i4;
            }
            c1034v.y.icon = i3;
            c1034v.j = 2;
            if (com.google.android.gms.common.util.c.m(context)) {
                c1034v.b.add(new C1029p(IconCompat.a(null, "", 2131230981), resources.getString(com.quizlet.quizletandroid.R.string.common_open_on_phone), pendingIntent, new Bundle(), null, null));
            } else {
                c1034v.g = pendingIntent;
            }
        } else {
            c1034v.y.icon = R.drawable.stat_sys_warning;
            c1034v.y.tickerText = C1034v.b(resources.getString(com.quizlet.quizletandroid.R.string.common_google_play_services_notification_ticker));
            c1034v.y.when = System.currentTimeMillis();
            c1034v.g = pendingIntent;
            c1034v.f = C1034v.b(strD);
        }
        synchronized (c) {
        }
        NotificationChannel notificationChannel = notificationManager.getNotificationChannel("com.google.android.gms.availability");
        String string = context.getResources().getString(com.quizlet.quizletandroid.R.string.common_google_play_services_notification_channel_name);
        if (notificationChannel == null) {
            notificationManager.createNotificationChannel(new NotificationChannel("com.google.android.gms.availability", string, 4));
        } else if (!string.contentEquals(notificationChannel.getName())) {
            notificationChannel.setName(string);
            notificationManager.createNotificationChannel(notificationChannel);
        }
        c1034v.v = "com.google.android.gms.availability";
        Notification notificationA = c1034v.a();
        if (i == 1 || i == 2 || i == 3) {
            d.a.set(false);
            i2 = 10436;
        } else {
            i2 = 39789;
        }
        notificationManager.notify(i2, notificationA);
    }
}

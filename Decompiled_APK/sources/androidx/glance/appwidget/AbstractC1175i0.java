package androidx.glance.appwidget;

import android.appwidget.AppWidgetManager;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Build;
import android.widget.RemoteViews;
import kotlin.Unit;
import org.jetbrains.annotations.NotNull;

/* renamed from: androidx.glance.appwidget.i0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractC1175i0 {
    public static final void a(@NotNull RemoteViews remoteViews, @NotNull Context context, int i, int i2, @NotNull String str, @NotNull z0 z0Var) {
        if (Build.VERSION.SDK_INT > 31) {
            C1216t.a.a(remoteViews, i2, z0Var);
            return;
        }
        Intent intentPutExtra = new Intent(context, (Class<?>) GlanceRemoteViewsService.class).putExtra("appWidgetId", i).putExtra("androidx.glance.widget.extra.view_id", i2).putExtra("androidx.glance.widget.extra.size_info", str);
        intentPutExtra.setData(Uri.parse(intentPutExtra.toUri(1)));
        if (context.getPackageManager().resolveService(intentPutExtra, 0) == null) {
            throw new IllegalStateException("GlanceRemoteViewsService could not be resolved, check the app manifest.");
        }
        remoteViews.setRemoteAdapter(i2, intentPutExtra);
        androidx.camera.core.impl.y0 y0Var = GlanceRemoteViewsService.a;
        synchronized (y0Var) {
            y0Var.a.put(androidx.camera.core.impl.y0.e(i, i2, str), z0Var);
            Unit unit = Unit.a;
        }
        AppWidgetManager.getInstance(context).notifyAppWidgetViewDataChanged(i, i2);
    }
}

package androidx.glance.appwidget;

import android.widget.RemoteViews;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class C0 {
    public static final C0 a = new C0();

    public final void a(@NotNull RemoteViews remoteViews, int i, @NotNull RemoteViews remoteViews2, int i2) {
        remoteViews.addStableView(i, remoteViews2, i2);
    }
}

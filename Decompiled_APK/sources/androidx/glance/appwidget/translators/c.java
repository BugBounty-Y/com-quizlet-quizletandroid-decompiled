package androidx.glance.appwidget.translators;

import android.os.Build;
import android.widget.RemoteViews;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class c {
    public static final c a = new c();

    public final void a(@NotNull RemoteViews remoteViews, int i, int i2) {
        Intrinsics.checkNotNullParameter(remoteViews, "<this>");
        if (Build.VERSION.SDK_INT >= 31) {
            remoteViews.setInt(i, "setGravity", i2);
            return;
        }
        throw new IllegalArgumentException(("setGravity is only available on SDK 31 and higher").toString());
    }
}

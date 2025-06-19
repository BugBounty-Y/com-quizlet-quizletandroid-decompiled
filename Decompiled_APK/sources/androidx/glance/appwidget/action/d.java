package androidx.glance.appwidget.action;

import android.content.Context;
import android.content.Intent;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class d {
    public static final d a = new d();

    public final void a(@NotNull Context context, @NotNull Intent intent) {
        context.startForegroundService(intent);
    }
}

package androidx.glance.appwidget;

import android.widget.RemoteViews;
import org.jetbrains.annotations.NotNull;

/* renamed from: androidx.glance.appwidget.t, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1216t {
    public static final C1216t a = new C1216t();

    public final void a(@NotNull RemoteViews remoteViews, int i, @NotNull z0 z0Var) {
        remoteViews.setRemoteAdapter(i, b(z0Var));
    }

    @NotNull
    public final RemoteViews.RemoteCollectionItems b(@NotNull z0 z0Var) {
        RemoteViews.RemoteCollectionItems.Builder viewTypeCount = new RemoteViews.RemoteCollectionItems.Builder().setHasStableIds(z0Var.c).setViewTypeCount(z0Var.d);
        long[] jArr = z0Var.a;
        int length = jArr.length;
        for (int i = 0; i < length; i++) {
            viewTypeCount.addItem(jArr[i], z0Var.b[i]);
        }
        return viewTypeCount.build();
    }
}

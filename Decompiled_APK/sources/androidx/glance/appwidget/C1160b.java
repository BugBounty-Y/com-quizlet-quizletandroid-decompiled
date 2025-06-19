package androidx.glance.appwidget;

import android.util.SizeF;
import android.widget.RemoteViews;
import java.util.Map;
import org.jetbrains.annotations.NotNull;

/* renamed from: androidx.glance.appwidget.b, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1160b {
    public static final C1160b a = new C1160b();

    @NotNull
    public final RemoteViews a(@NotNull Map<SizeF, ? extends RemoteViews> map) {
        return new RemoteViews((Map<SizeF, RemoteViews>) map);
    }
}

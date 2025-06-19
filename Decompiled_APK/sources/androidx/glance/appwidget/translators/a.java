package androidx.glance.appwidget.translators;

import android.widget.RemoteViews;
import androidx.compose.ui.graphics.F;
import androidx.core.widget.j;
import androidx.glance.appwidget.N0;
import androidx.glance.unit.i;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class a {
    public static final a a = new a();

    public final void a(@NotNull N0 n0, @NotNull RemoteViews remoteViews, @NotNull androidx.glance.unit.a aVar, int i) {
        if (aVar instanceof androidx.glance.color.a) {
            androidx.glance.color.a aVar2 = (androidx.glance.color.a) aVar;
            int iA = F.A(aVar2.a);
            int iA2 = F.A(aVar2.b);
            Intrinsics.checkNotNullParameter(remoteViews, "<this>");
            j.f(remoteViews, i, "setColorFilter", iA, iA2);
            return;
        }
        if (aVar instanceof i) {
            int i2 = ((i) aVar).a;
            Intrinsics.checkNotNullParameter(remoteViews, "<this>");
            j.d(remoteViews, i, "setColorFilter", i2);
        } else {
            int iA3 = F.A(aVar.a(n0.a));
            Intrinsics.checkNotNullParameter(remoteViews, "<this>");
            remoteViews.setInt(i, "setColorFilter", iA3);
        }
    }
}

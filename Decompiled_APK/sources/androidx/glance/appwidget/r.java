package androidx.glance.appwidget;

import android.os.Build;
import android.widget.RemoteViews;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class r {
    public static final r a = new r();

    public final void a(@NotNull RemoteViews remoteViews, int i, @NotNull androidx.glance.unit.g gVar) {
        Intrinsics.checkNotNullParameter(remoteViews, "<this>");
        if (Build.VERSION.SDK_INT < 31) {
            throw new IllegalArgumentException(("setClipToOutline is only available on SDK 31 and higher").toString());
        }
        remoteViews.setBoolean(i, "setClipToOutline", true);
        if (gVar instanceof androidx.glance.unit.c) {
            remoteViews.setViewOutlinePreferredRadius(i, ((androidx.glance.unit.c) gVar).a, 1);
        } else {
            throw new IllegalStateException(("Rounded corners should not be " + gVar.getClass().getCanonicalName()).toString());
        }
    }

    public final void b(@NotNull RemoteViews remoteViews, int i, @NotNull androidx.glance.unit.g gVar) {
        if (gVar instanceof androidx.glance.unit.f) {
            remoteViews.setViewLayoutHeight(i, -2.0f, 0);
        } else if (gVar instanceof androidx.glance.unit.d) {
            remoteViews.setViewLayoutHeight(i, DefinitionKt.NO_Float_VALUE, 0);
        } else if (gVar instanceof androidx.glance.unit.c) {
            remoteViews.setViewLayoutHeight(i, ((androidx.glance.unit.c) gVar).a, 1);
        } else {
            if (!Intrinsics.b(gVar, androidx.glance.unit.e.a)) {
                throw new NoWhenBranchMatchedException();
            }
            remoteViews.setViewLayoutHeight(i, -1.0f, 0);
        }
        Unit unit = Unit.a;
    }

    public final void c(@NotNull RemoteViews remoteViews, int i, @NotNull androidx.glance.unit.g gVar) {
        if (gVar instanceof androidx.glance.unit.f) {
            remoteViews.setViewLayoutWidth(i, -2.0f, 0);
        } else if (gVar instanceof androidx.glance.unit.d) {
            remoteViews.setViewLayoutWidth(i, DefinitionKt.NO_Float_VALUE, 0);
        } else if (gVar instanceof androidx.glance.unit.c) {
            remoteViews.setViewLayoutWidth(i, ((androidx.glance.unit.c) gVar).a, 1);
        } else {
            if (!Intrinsics.b(gVar, androidx.glance.unit.e.a)) {
                throw new NoWhenBranchMatchedException();
            }
            remoteViews.setViewLayoutWidth(i, -1.0f, 0);
        }
        Unit unit = Unit.a;
    }
}

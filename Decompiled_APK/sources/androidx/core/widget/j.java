package androidx.core.widget;

import android.content.res.ColorStateList;
import android.graphics.BlendMode;
import android.graphics.drawable.Icon;
import android.widget.RemoteViews;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public abstract class j {
    public static final void a(@NotNull RemoteViews rv, int i, @NotNull String method, BlendMode blendMode) {
        Intrinsics.checkNotNullParameter(rv, "rv");
        Intrinsics.checkNotNullParameter(method, "method");
        rv.setBlendMode(i, method, blendMode);
    }

    public static final void b(@NotNull RemoteViews rv, int i, @NotNull String method, int i2) {
        Intrinsics.checkNotNullParameter(rv, "rv");
        Intrinsics.checkNotNullParameter(method, "method");
        rv.setCharSequence(i, method, i2);
    }

    public static final void c(@NotNull RemoteViews rv, int i, @NotNull String method, int i2) {
        Intrinsics.checkNotNullParameter(rv, "rv");
        Intrinsics.checkNotNullParameter(method, "method");
        rv.setCharSequenceAttr(i, method, i2);
    }

    public static final void d(@NotNull RemoteViews rv, int i, @NotNull String method, int i2) {
        Intrinsics.checkNotNullParameter(rv, "rv");
        Intrinsics.checkNotNullParameter(method, "method");
        rv.setColor(i, method, i2);
    }

    public static final void e(@NotNull RemoteViews rv, int i, @NotNull String method, int i2) {
        Intrinsics.checkNotNullParameter(rv, "rv");
        Intrinsics.checkNotNullParameter(method, "method");
        rv.setColorAttr(i, method, i2);
    }

    public static final void f(@NotNull RemoteViews rv, int i, @NotNull String method, int i2, int i3) {
        Intrinsics.checkNotNullParameter(rv, "rv");
        Intrinsics.checkNotNullParameter(method, "method");
        rv.setColorInt(i, method, i2, i3);
    }

    public static final void g(@NotNull RemoteViews rv, int i, @NotNull String method, int i2) {
        Intrinsics.checkNotNullParameter(rv, "rv");
        Intrinsics.checkNotNullParameter(method, "method");
        rv.setColorStateList(i, method, i2);
    }

    public static final void h(@NotNull RemoteViews rv, int i, @NotNull String method, ColorStateList colorStateList) {
        Intrinsics.checkNotNullParameter(rv, "rv");
        Intrinsics.checkNotNullParameter(method, "method");
        rv.setColorStateList(i, method, colorStateList);
    }

    public static final void i(@NotNull RemoteViews rv, int i, @NotNull String method, ColorStateList colorStateList, ColorStateList colorStateList2) {
        Intrinsics.checkNotNullParameter(rv, "rv");
        Intrinsics.checkNotNullParameter(method, "method");
        rv.setColorStateList(i, method, colorStateList, colorStateList2);
    }

    public static final void j(@NotNull RemoteViews rv, int i, @NotNull String method, int i2) {
        Intrinsics.checkNotNullParameter(rv, "rv");
        Intrinsics.checkNotNullParameter(method, "method");
        rv.setColorStateListAttr(i, method, i2);
    }

    public static final void k(@NotNull RemoteViews rv, int i, @NotNull String method, float f, int i2) {
        Intrinsics.checkNotNullParameter(rv, "rv");
        Intrinsics.checkNotNullParameter(method, "method");
        rv.setFloatDimen(i, method, f, i2);
    }

    public static final void l(@NotNull RemoteViews rv, int i, @NotNull String method, int i2) {
        Intrinsics.checkNotNullParameter(rv, "rv");
        Intrinsics.checkNotNullParameter(method, "method");
        rv.setFloatDimen(i, method, i2);
    }

    public static final void m(@NotNull RemoteViews rv, int i, @NotNull String method, int i2) {
        Intrinsics.checkNotNullParameter(rv, "rv");
        Intrinsics.checkNotNullParameter(method, "method");
        rv.setFloatDimenAttr(i, method, i2);
    }

    public static final void n(@NotNull RemoteViews rv, int i, @NotNull String method, Icon icon, Icon icon2) {
        Intrinsics.checkNotNullParameter(rv, "rv");
        Intrinsics.checkNotNullParameter(method, "method");
        rv.setIcon(i, method, icon, icon2);
    }

    public static final void o(@NotNull RemoteViews rv, int i, @NotNull String method, float f, int i2) {
        Intrinsics.checkNotNullParameter(rv, "rv");
        Intrinsics.checkNotNullParameter(method, "method");
        rv.setIntDimen(i, method, f, i2);
    }

    public static final void p(@NotNull RemoteViews rv, int i, @NotNull String method, int i2) {
        Intrinsics.checkNotNullParameter(rv, "rv");
        Intrinsics.checkNotNullParameter(method, "method");
        rv.setIntDimen(i, method, i2);
    }

    public static final void q(@NotNull RemoteViews rv, int i, @NotNull String method, int i2) {
        Intrinsics.checkNotNullParameter(rv, "rv");
        Intrinsics.checkNotNullParameter(method, "method");
        rv.setIntDimenAttr(i, method, i2);
    }
}

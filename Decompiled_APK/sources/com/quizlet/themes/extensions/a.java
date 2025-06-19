package com.quizlet.themes.extensions;

import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.drawable.Drawable;
import android.util.TypedValue;
import androidx.core.content.c;
import com.quizlet.baseui.base.f;
import com.quizlet.quizletandroid.ui.startpage.nav2.composables.b;
import kotlin.jvm.internal.Intrinsics;
import kotlin.l;
import kotlin.u;

/* loaded from: classes3.dex */
public abstract class a {
    public static final u a = l.b(new b(22));

    public static final int a(Context context, int i) {
        Intrinsics.checkNotNullParameter(context, "<this>");
        context.getTheme().resolveAttribute(i, b(), true);
        return b().data;
    }

    public static final TypedValue b() {
        return (TypedValue) a.getValue();
    }

    public static final Drawable c(Context context, int i, int i2) {
        Drawable drawableMutate;
        Intrinsics.checkNotNullParameter(context, "<this>");
        Drawable drawable = context.getDrawable(i);
        if (drawable == null || (drawableMutate = drawable.mutate()) == null) {
            return null;
        }
        drawableMutate.setTint(a(context, i2));
        return drawableMutate;
    }

    public static final Drawable d(f fVar, int i, int i2) {
        Drawable drawableMutate;
        Intrinsics.checkNotNullParameter(fVar, "<this>");
        fVar.getTheme().resolveAttribute(i2, b(), true);
        ColorStateList colorStateListC = c.c(fVar, b().resourceId);
        Drawable drawable = fVar.getDrawable(i);
        if (drawable == null || (drawableMutate = drawable.mutate()) == null) {
            return null;
        }
        drawableMutate.setTintList(colorStateListC);
        return drawableMutate;
    }
}

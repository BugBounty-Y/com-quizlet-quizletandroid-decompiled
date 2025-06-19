package com.skydoves.balloon.extensions;

import android.content.Context;
import android.graphics.drawable.Drawable;
import com.facebook.appevents.g;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class ContextExtensionKt {
    public static final int contextColor(Context context, int i) {
        Intrinsics.checkNotNullParameter(context, "<this>");
        return context.getColor(i);
    }

    public static final /* synthetic */ Drawable contextDrawable(Context context, int i) {
        Intrinsics.checkNotNullParameter(context, "<this>");
        return g.f(context, i);
    }

    public static final /* synthetic */ float dimen(Context context, int i) {
        Intrinsics.checkNotNullParameter(context, "<this>");
        return context.getResources().getDimension(i);
    }

    public static final /* synthetic */ int dimenPixel(Context context, int i) {
        Intrinsics.checkNotNullParameter(context, "<this>");
        return context.getResources().getDimensionPixelSize(i);
    }

    public static final /* synthetic */ float px2Sp(Context context, float f) {
        Intrinsics.checkNotNullParameter(context, "<this>");
        return f / context.getResources().getDisplayMetrics().scaledDensity;
    }
}

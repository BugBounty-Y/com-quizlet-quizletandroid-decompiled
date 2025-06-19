package com.skydoves.balloon.extensions;

import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.drawable.BitmapDrawable;
import android.graphics.drawable.Drawable;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class DrawableExtensionKt {
    public static final /* synthetic */ int getHeight(Drawable drawable) {
        if (drawable != null) {
            return drawable.getIntrinsicHeight();
        }
        return 0;
    }

    public static final int getIntrinsicHeight(Drawable[] drawableArr) {
        Intrinsics.checkNotNullParameter(drawableArr, "<this>");
        int height = getHeight(drawableArr[0]);
        int height2 = getHeight(drawableArr[2]);
        return height < height2 ? height2 : height;
    }

    public static final /* synthetic */ int getSumOfIntrinsicWidth(Drawable[] drawableArr) {
        Intrinsics.checkNotNullParameter(drawableArr, "<this>");
        return getWidth(drawableArr[2]) + getWidth(drawableArr[0]);
    }

    public static final /* synthetic */ int getWidth(Drawable drawable) {
        if (drawable != null) {
            return drawable.getIntrinsicWidth();
        }
        return 0;
    }

    public static final /* synthetic */ boolean isExistHorizontalDrawable(Drawable[] drawableArr) {
        Intrinsics.checkNotNullParameter(drawableArr, "<this>");
        return (drawableArr[0] == null && drawableArr[2] == null) ? false : true;
    }

    public static final /* synthetic */ Drawable resize(Drawable drawable, Context context, Integer num, Integer num2) {
        Intrinsics.checkNotNullParameter(drawable, "<this>");
        Intrinsics.checkNotNullParameter(context, "context");
        if (num == null || num2 == null) {
            return drawable;
        }
        Bitmap bitmapCreateBitmap = Bitmap.createBitmap(num.intValue(), num2.intValue(), Bitmap.Config.ARGB_8888);
        Intrinsics.checkNotNullExpressionValue(bitmapCreateBitmap, "createBitmap(...)");
        Canvas canvas = new Canvas(bitmapCreateBitmap);
        drawable.setBounds(0, 0, num.intValue(), num2.intValue());
        drawable.draw(canvas);
        return new BitmapDrawable(context.getResources(), bitmapCreateBitmap);
    }

    public static final Drawable tint(Drawable drawable, Integer num) {
        Intrinsics.checkNotNullParameter(drawable, "<this>");
        if (num != null) {
            drawable.setTintList(ColorStateList.valueOf(num.intValue()));
        }
        return drawable;
    }
}

package com.google.android.material.datepicker;

import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.Rect;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3442d4;

/* loaded from: classes2.dex */
public final class c {
    public static c a(Context context, int i) {
        AbstractC3242q6.c("Cannot create a CalendarItemStyle with a styleResId of 0", i != 0);
        TypedArray typedArrayObtainStyledAttributes = context.obtainStyledAttributes(i, com.google.android.material.a.y);
        Rect rect = new Rect(typedArrayObtainStyledAttributes.getDimensionPixelOffset(0, 0), typedArrayObtainStyledAttributes.getDimensionPixelOffset(2, 0), typedArrayObtainStyledAttributes.getDimensionPixelOffset(1, 0), typedArrayObtainStyledAttributes.getDimensionPixelOffset(3, 0));
        AbstractC3442d4.a(context, typedArrayObtainStyledAttributes, 4);
        AbstractC3442d4.a(context, typedArrayObtainStyledAttributes, 9);
        AbstractC3442d4.a(context, typedArrayObtainStyledAttributes, 7);
        typedArrayObtainStyledAttributes.getDimensionPixelSize(8, 0);
        com.google.android.material.shape.j.a(context, typedArrayObtainStyledAttributes.getResourceId(5, 0), typedArrayObtainStyledAttributes.getResourceId(6, 0), new com.google.android.material.shape.a(0)).a();
        typedArrayObtainStyledAttributes.recycle();
        c cVar = new c();
        AbstractC3242q6.f(rect.left);
        AbstractC3242q6.f(rect.top);
        AbstractC3242q6.f(rect.right);
        AbstractC3242q6.f(rect.bottom);
        return cVar;
    }
}

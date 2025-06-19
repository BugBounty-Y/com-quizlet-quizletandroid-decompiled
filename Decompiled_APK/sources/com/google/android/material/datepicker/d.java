package com.google.android.material.datepicker;

import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.Resources;
import android.content.res.TypedArray;
import android.graphics.Paint;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3436c4;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3442d4;
import com.quizlet.quizletandroid.R;

/* loaded from: classes2.dex */
public final class d {
    public final c a;
    public final c b;

    public d(Context context) throws Resources.NotFoundException {
        TypedArray typedArrayObtainStyledAttributes = context.obtainStyledAttributes(AbstractC3436c4.d(context, k.class.getCanonicalName(), R.attr.materialCalendarStyle).data, com.google.android.material.a.x);
        c.a(context, typedArrayObtainStyledAttributes.getResourceId(4, 0));
        c.a(context, typedArrayObtainStyledAttributes.getResourceId(2, 0));
        c.a(context, typedArrayObtainStyledAttributes.getResourceId(3, 0));
        c.a(context, typedArrayObtainStyledAttributes.getResourceId(5, 0));
        ColorStateList colorStateListA = AbstractC3442d4.a(context, typedArrayObtainStyledAttributes, 7);
        this.a = c.a(context, typedArrayObtainStyledAttributes.getResourceId(9, 0));
        c.a(context, typedArrayObtainStyledAttributes.getResourceId(8, 0));
        this.b = c.a(context, typedArrayObtainStyledAttributes.getResourceId(10, 0));
        new Paint().setColor(colorStateListA.getDefaultColor());
        typedArrayObtainStyledAttributes.recycle();
    }
}

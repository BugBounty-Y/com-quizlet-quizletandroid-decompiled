package com.quizlet.partskit.widgets;

import android.content.Context;
import android.content.res.TypedArray;
import android.util.AttributeSet;
import androidx.appcompat.widget.D;
import androidx.core.content.res.k;
import com.quizlet.themes.u;
import com.quizlet.ui.resources.designsystem.generated.a;

/* loaded from: classes3.dex */
public class QRadioButton extends D {
    public QRadioButton(Context context) {
        super(context);
        TypedArray typedArrayObtainStyledAttributes = context.obtainStyledAttributes((AttributeSet) null, u.e);
        int resourceId = typedArrayObtainStyledAttributes.getResourceId(1, a.b);
        int i = typedArrayObtainStyledAttributes.getInt(0, 0);
        typedArrayObtainStyledAttributes.recycle();
        setTypeface(k.a(context, resourceId), i);
    }

    public QRadioButton(Context context, AttributeSet attributeSet) {
        super(context, attributeSet, 0);
        TypedArray typedArrayObtainStyledAttributes = context.obtainStyledAttributes(attributeSet, u.e);
        int resourceId = typedArrayObtainStyledAttributes.getResourceId(1, a.b);
        int i = typedArrayObtainStyledAttributes.getInt(0, 0);
        typedArrayObtainStyledAttributes.recycle();
        setTypeface(k.a(context, resourceId), i);
    }
}

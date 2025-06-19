package com.quizlet.partskit.widgets;

import android.content.Context;
import android.content.res.TypedArray;
import android.util.AttributeSet;
import androidx.appcompat.widget.r;
import androidx.compose.ui.text.font.m;
import androidx.core.content.res.k;
import com.quizlet.quizletandroid.R;
import com.quizlet.themes.u;
import com.quizlet.ui.resources.designsystem.generated.a;

/* loaded from: classes3.dex */
public class QCheckBox extends r {
    public QCheckBox(Context context) {
        super(context);
        a(context, null);
    }

    public final void a(Context context, AttributeSet attributeSet) {
        TypedArray typedArrayObtainStyledAttributes = context.obtainStyledAttributes(attributeSet, u.c, 0, R.style.QuizletButton);
        m mVar = a.a;
        int resourceId = typedArrayObtainStyledAttributes.getResourceId(1, a.b);
        int i = typedArrayObtainStyledAttributes.getInt(0, 0);
        typedArrayObtainStyledAttributes.recycle();
        setTypeface(k.a(context, resourceId), i);
    }

    public QCheckBox(Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
        a(context, attributeSet);
    }
}

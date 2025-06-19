package com.quizlet.partskit.widgets;

import android.content.Context;
import android.content.res.TypedArray;
import android.util.AttributeSet;
import androidx.appcompat.widget.AppCompatTextView;
import androidx.compose.ui.text.font.m;
import androidx.core.content.res.k;
import com.quizlet.themes.u;
import com.quizlet.ui.resources.designsystem.generated.a;

/* loaded from: classes3.dex */
public class QTextView extends AppCompatTextView {
    public QTextView(Context context) {
        super(context);
        e(context, null);
    }

    public final void e(Context context, AttributeSet attributeSet) {
        TypedArray typedArrayObtainStyledAttributes = context.obtainStyledAttributes(attributeSet, u.f);
        m mVar = a.a;
        int resourceId = typedArrayObtainStyledAttributes.getResourceId(1, a.b);
        int i = typedArrayObtainStyledAttributes.getInt(0, 0);
        typedArrayObtainStyledAttributes.recycle();
        if (isInEditMode()) {
            return;
        }
        setTypeface(k.a(context, resourceId), i);
    }

    public QTextView(Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
        e(context, attributeSet);
    }

    public QTextView(Context context, AttributeSet attributeSet, int i) {
        super(context, attributeSet, 0);
        e(context, attributeSet);
    }
}

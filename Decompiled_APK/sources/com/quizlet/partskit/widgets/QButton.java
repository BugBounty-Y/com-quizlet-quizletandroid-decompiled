package com.quizlet.partskit.widgets;

import android.content.Context;
import android.content.res.TypedArray;
import android.util.AttributeSet;
import androidx.appcompat.widget.AppCompatButton;
import com.quizlet.quizletandroid.R;
import com.quizlet.themes.extensions.a;
import com.quizlet.themes.u;

/* loaded from: classes3.dex */
public class QButton extends AppCompatButton {
    public QButton(Context context) {
        super(context);
        a(context, null);
    }

    public final void a(Context context, AttributeSet attributeSet) {
        TypedArray typedArrayObtainStyledAttributes = context.obtainStyledAttributes(attributeSet, u.b, 0, R.style.QuizletButton);
        int resourceId = typedArrayObtainStyledAttributes.getResourceId(0, R.style.Header_H5);
        int color = typedArrayObtainStyledAttributes.getColor(1, a.a(getContext(), R.attr.AssemblyPrimaryButtonText));
        typedArrayObtainStyledAttributes.recycle();
        setTextAppearance(getContext(), resourceId);
        setTextColor(color);
    }

    public QButton(Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
        a(context, attributeSet);
    }
}

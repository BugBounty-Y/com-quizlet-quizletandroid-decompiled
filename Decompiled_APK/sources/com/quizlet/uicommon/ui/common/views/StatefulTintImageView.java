package com.quizlet.uicommon.ui.common.views;

import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.TypedArray;
import android.graphics.Color;
import android.util.AttributeSet;
import androidx.appcompat.widget.AppCompatImageView;
import com.quizlet.quizletandroid.ui.common.a;

/* loaded from: classes3.dex */
public class StatefulTintImageView extends AppCompatImageView {
    public ColorStateList d;

    public StatefulTintImageView(Context context) {
        this(context, null);
    }

    @Override // androidx.appcompat.widget.AppCompatImageView, android.widget.ImageView, android.view.View
    public final void drawableStateChanged() {
        super.drawableStateChanged();
        ColorStateList colorStateList = this.d;
        if (colorStateList == null || !colorStateList.isStateful()) {
            return;
        }
        setColorFilter(this.d.getColorForState(getDrawableState(), 0));
        setAlpha(Color.alpha(r0) / 255.0f);
    }

    public void setTintColor(int i) {
        this.d = null;
        setColorFilter(i);
    }

    public StatefulTintImageView(Context context, AttributeSet attributeSet) {
        super(context, attributeSet, 0);
        if (attributeSet == null) {
            this.d = null;
            return;
        }
        TypedArray typedArrayObtainStyledAttributes = context.obtainStyledAttributes(attributeSet, a.f);
        this.d = typedArrayObtainStyledAttributes.getColorStateList(0);
        typedArrayObtainStyledAttributes.recycle();
    }
}

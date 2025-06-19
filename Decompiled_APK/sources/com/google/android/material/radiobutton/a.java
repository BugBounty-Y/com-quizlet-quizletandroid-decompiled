package com.google.android.material.radiobutton;

import android.R;
import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.TypedArray;
import android.util.AttributeSet;
import androidx.annotation.NonNull;
import androidx.appcompat.widget.D;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3442d4;
import com.google.android.gms.internal.mlkit_vision_common.X3;
import com.google.android.material.internal.p;

/* loaded from: classes2.dex */
public class a extends D {
    public static final int[][] g = {new int[]{R.attr.state_enabled, R.attr.state_checked}, new int[]{R.attr.state_enabled, -16842912}, new int[]{-16842910, R.attr.state_checked}, new int[]{-16842910, -16842912}};
    public ColorStateList e;
    public boolean f;

    public a(@NonNull Context context) {
        this(context, null, 0);
    }

    private ColorStateList getMaterialThemeColorsTintList() {
        if (this.e == null) {
            int iB = X3.b(com.quizlet.quizletandroid.R.attr.colorControlActivated, this);
            int iB2 = X3.b(com.quizlet.quizletandroid.R.attr.colorOnSurface, this);
            int iB3 = X3.b(com.quizlet.quizletandroid.R.attr.colorSurface, this);
            this.e = new ColorStateList(g, new int[]{X3.e(iB3, 1.0f, iB), X3.e(iB3, 0.54f, iB2), X3.e(iB3, 0.38f, iB2), X3.e(iB3, 0.38f, iB2)});
        }
        return this.e;
    }

    @Override // android.widget.TextView, android.view.View
    public final void onAttachedToWindow() {
        super.onAttachedToWindow();
        if (this.f && getButtonTintList() == null) {
            setUseMaterialThemeColors(true);
        }
    }

    public void setUseMaterialThemeColors(boolean z) {
        this.f = z;
        if (z) {
            setButtonTintList(getMaterialThemeColorsTintList());
        } else {
            setButtonTintList(null);
        }
    }

    public a(Context context, AttributeSet attributeSet, int i) {
        super(com.google.android.material.theme.overlay.a.a(context, attributeSet, com.quizlet.quizletandroid.R.attr.radioButtonStyle, com.quizlet.quizletandroid.R.style.Widget_MaterialComponents_CompoundButton_RadioButton), attributeSet, 0);
        Context context2 = getContext();
        TypedArray typedArrayL = p.l(context2, attributeSet, com.google.android.material.a.B, com.quizlet.quizletandroid.R.attr.radioButtonStyle, com.quizlet.quizletandroid.R.style.Widget_MaterialComponents_CompoundButton_RadioButton, new int[0]);
        if (typedArrayL.hasValue(0)) {
            setButtonTintList(AbstractC3442d4.a(context2, typedArrayL, 0));
        }
        this.f = typedArrayL.getBoolean(1, false);
        typedArrayL.recycle();
    }
}

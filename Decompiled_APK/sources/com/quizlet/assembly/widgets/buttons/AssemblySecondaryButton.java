package com.quizlet.assembly.widgets.buttons;

import android.content.Context;
import android.content.res.ColorStateList;
import android.util.AttributeSet;
import com.quizlet.quizletandroid.R;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class AssemblySecondaryButton extends d {
    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public AssemblySecondaryButton(@NotNull Context context) {
        this(context, null, 6);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    public final void setDrawablePadding(float f) {
        getBinding().d.setCompoundDrawablePadding((int) f);
    }

    public final void setDrawableStart(int i) {
        getBinding().d.setCompoundDrawablesWithIntrinsicBounds(i, 0, 0, 0);
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public AssemblySecondaryButton(@NotNull Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 4);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public AssemblySecondaryButton(Context context, AttributeSet attributeSet, int i) {
        attributeSet = (i & 2) != 0 ? null : attributeSet;
        Intrinsics.checkNotNullParameter(context, "context");
        super(context, attributeSet);
        setBackgroundResource(R.drawable.assembly_secondary_button_background);
        ColorStateList colorStateList = context.getColorStateList(R.color.assembly_secondary_icon_text);
        Intrinsics.checkNotNullExpressionValue(colorStateList, "getColorStateList(...)");
        getBinding().d.setTextColor(colorStateList);
        setIconTint(colorStateList);
    }
}

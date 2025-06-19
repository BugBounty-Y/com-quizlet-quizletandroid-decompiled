package com.quizlet.partskit.widgets.icon;

import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.TypedArray;
import android.util.AttributeSet;
import android.util.StateSet;
import com.quizlet.quizletandroid.R;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class StatefulIconFontTextView extends IconFontTextView {
    public final AttributeSet f;

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public StatefulIconFontTextView(@NotNull Context context) {
        this(context, null, 6);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    public final AttributeSet getAttrs() {
        return this.f;
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public StatefulIconFontTextView(@NotNull Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 4);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public StatefulIconFontTextView(Context context, AttributeSet attributeSet, int i) {
        AttributeSet attributeSet2 = (i & 2) != 0 ? null : attributeSet;
        Intrinsics.checkNotNullParameter(context, "context");
        super(context, attributeSet2, 0);
        this.f = attributeSet2;
        int iA = com.quizlet.themes.extensions.a.a(context, R.attr.colorControlEnabled);
        if (attributeSet2 != null) {
            TypedArray typedArrayObtainStyledAttributes = context.obtainStyledAttributes(attributeSet2, com.quizlet.partskit.a.a);
            Intrinsics.checkNotNullExpressionValue(typedArrayObtainStyledAttributes, "obtainStyledAttributes(...)");
            ColorStateList colorStateList = typedArrayObtainStyledAttributes.getColorStateList(0);
            iA = colorStateList != null ? colorStateList.getDefaultColor() : iA;
            typedArrayObtainStyledAttributes.recycle();
        }
        Intrinsics.checkNotNullParameter(context, "<this>");
        int iA2 = com.quizlet.themes.extensions.a.a(context, R.attr.stateActivated);
        int iA3 = com.quizlet.themes.extensions.a.a(context, R.attr.stateSuccess);
        setTextColor(new ColorStateList(new int[][]{new int[]{android.R.attr.state_pressed}, new int[]{android.R.attr.state_selected}, new int[]{R.attr.state_validated, R.attr.state_success, android.R.attr.state_focused}, new int[]{R.attr.state_validated, R.attr.state_success, R.attr.state_edittext_focus}, new int[]{R.attr.state_validated, -2130970284}, new int[]{android.R.attr.state_focused}, new int[]{-16842910}, StateSet.WILD_CARD}, new int[]{iA2, iA2, iA3, iA3, com.quizlet.themes.extensions.a.a(context, R.attr.stateError), iA2, com.quizlet.themes.extensions.a.a(context, R.attr.stateDisabled), iA}));
    }
}

package com.quizlet.assembly.widgets.radio;

import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.TypedArray;
import android.util.AttributeSet;
import android.util.StateSet;
import com.quizlet.quizletandroid.R;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class AssemblyRadioButton extends com.google.android.material.radiobutton.a {
    public a h;

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public AssemblyRadioButton(@NotNull Context context) {
        this(context, null, 6);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    private final int getDefaultButtonTint() {
        int i;
        Context context = getContext();
        Intrinsics.checkNotNullExpressionValue(context, "getContext(...)");
        int iOrdinal = this.h.ordinal();
        if (iOrdinal == 0) {
            i = R.attr.SysColorTextPrimary;
        } else if (iOrdinal == 1) {
            i = R.attr.AssemblyIconColorDisabled;
        } else {
            if (iOrdinal != 2) {
                throw new NoWhenBranchMatchedException();
            }
            i = R.attr.SysColorError;
        }
        return com.quizlet.themes.extensions.a.a(context, i);
    }

    public final void a() {
        Context context = getContext();
        Intrinsics.checkNotNullExpressionValue(context, "getContext(...)");
        int iA = com.quizlet.themes.extensions.a.a(context, R.attr.AssemblyDisabledTintColor);
        int defaultButtonTint = getDefaultButtonTint();
        setButtonTintList(new ColorStateList(new int[][]{new int[]{android.R.attr.state_enabled, -16842912}, new int[]{android.R.attr.state_enabled, android.R.attr.state_checked}, new int[]{-16842910}, StateSet.WILD_CARD}, new int[]{defaultButtonTint, defaultButtonTint, iA, defaultButtonTint}));
        Context context2 = getContext();
        Intrinsics.checkNotNullExpressionValue(context2, "getContext(...)");
        setTextColor(com.quizlet.themes.extensions.a.a(context2, (!isEnabled() || this.h == a.d) ? R.attr.AssemblyIconColorDisabled : R.attr.SysColorTextPrimary));
    }

    @NotNull
    public final a getVariant() {
        return this.h;
    }

    @Override // android.widget.TextView, android.view.View
    public void setEnabled(boolean z) {
        super.setEnabled(z);
        a();
    }

    public final void setVariant(@NotNull a value) {
        Intrinsics.checkNotNullParameter(value, "value");
        this.h = value;
        setEnabled(value != a.d);
        a();
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public AssemblyRadioButton(@NotNull Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 4);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public AssemblyRadioButton(Context context, AttributeSet attributeSet, int i) {
        a aVar = null;
        attributeSet = (i & 2) != 0 ? null : attributeSet;
        Intrinsics.checkNotNullParameter(context, "context");
        int i2 = 0;
        super(context, attributeSet, 0);
        this.h = a.c;
        TypedArray typedArrayObtainStyledAttributes = context.obtainStyledAttributes(attributeSet, com.quizlet.assembly.a.g);
        Intrinsics.checkNotNullExpressionValue(typedArrayObtainStyledAttributes, "obtainStyledAttributes(...)");
        try {
            int i3 = typedArrayObtainStyledAttributes.getInt(0, 0);
            setTextAppearance(R.style.SubHeader_S4);
            a.b.getClass();
            a[] aVarArrValues = a.values();
            int length = aVarArrValues.length;
            while (true) {
                if (i2 >= length) {
                    break;
                }
                a aVar2 = aVarArrValues[i2];
                if (aVar2.a == i3) {
                    aVar = aVar2;
                    break;
                }
                i2++;
            }
            if (aVar != null) {
                setVariant(aVar);
                setPadding(getResources().getDimensionPixelOffset(R.dimen.ref_spacing_xsmall), getPaddingTop(), getPaddingRight(), getPaddingBottom());
                typedArrayObtainStyledAttributes.recycle();
                a();
                return;
            }
            throw new IllegalArgumentException("Invalid AssemblyRadioButtonVariant");
        } catch (Throwable th) {
            typedArrayObtainStyledAttributes.recycle();
            throw th;
        }
    }
}

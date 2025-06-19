package com.quizlet.assembly.widgets.buttons;

import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.TypedArray;
import android.util.AttributeSet;
import com.quizlet.quizletandroid.R;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class AssemblyPrimaryButton extends d {
    public a x;

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public AssemblyPrimaryButton(@NotNull Context context) {
        this(context, null, 6);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    @NotNull
    public final a getVariant() {
        return this.x;
    }

    public final void r() {
        int i;
        ColorStateList colorStateListValueOf;
        int iOrdinal = this.x.ordinal();
        if (iOrdinal == 0) {
            i = R.drawable.primary_button_background;
        } else if (iOrdinal == 1) {
            i = R.drawable.danger_button_background;
        } else {
            if (iOrdinal != 2) {
                throw new NoWhenBranchMatchedException();
            }
            i = R.drawable.upgrade_button_background;
        }
        setBackgroundResource(i);
        int iOrdinal2 = this.x.ordinal();
        if (iOrdinal2 == 0) {
            Context context = getContext();
            Intrinsics.checkNotNullExpressionValue(context, "getContext(...)");
            colorStateListValueOf = ColorStateList.valueOf(com.quizlet.themes.extensions.a.a(context, R.attr.AssemblyPrimaryButtonText));
        } else if (iOrdinal2 == 1) {
            Context context2 = getContext();
            Intrinsics.checkNotNullExpressionValue(context2, "getContext(...)");
            colorStateListValueOf = ColorStateList.valueOf(com.quizlet.themes.extensions.a.a(context2, R.attr.AssemblyDangerActionText));
        } else {
            if (iOrdinal2 != 2) {
                throw new NoWhenBranchMatchedException();
            }
            colorStateListValueOf = getContext().getColorStateList(R.color.assembly_upgrade_button_text);
        }
        Intrinsics.d(colorStateListValueOf);
        getBinding().d.setTextColor(colorStateListValueOf);
        setIconTint(colorStateListValueOf);
    }

    public final void setDrawableEnd(int i) {
        getBinding().d.setCompoundDrawablesWithIntrinsicBounds(0, 0, i, 0);
    }

    public final void setDrawablePadding(float f) {
        getBinding().d.setCompoundDrawablePadding((int) f);
    }

    public final void setDrawableStart(int i) {
        getBinding().d.setCompoundDrawablesWithIntrinsicBounds(i, 0, 0, 0);
    }

    public final void setVariant(@NotNull a value) {
        Intrinsics.checkNotNullParameter(value, "value");
        this.x = value;
        r();
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public AssemblyPrimaryButton(@NotNull Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 4);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public AssemblyPrimaryButton(Context context, AttributeSet attributeSet, int i) {
        a aVar = null;
        attributeSet = (i & 2) != 0 ? null : attributeSet;
        Intrinsics.checkNotNullParameter(context, "context");
        super(context, attributeSet);
        this.x = a.c;
        TypedArray typedArrayObtainStyledAttributes = context.obtainStyledAttributes(attributeSet, com.quizlet.assembly.a.f);
        Intrinsics.checkNotNullExpressionValue(typedArrayObtainStyledAttributes, "obtainStyledAttributes(...)");
        int i2 = 0;
        try {
            int i3 = typedArrayObtainStyledAttributes.getInt(0, 0);
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
                typedArrayObtainStyledAttributes.recycle();
                r();
                return;
            }
            throw new IllegalArgumentException("Invalid AssemblyPrimaryButtonVariant");
        } catch (Throwable th) {
            typedArrayObtainStyledAttributes.recycle();
            throw th;
        }
    }
}

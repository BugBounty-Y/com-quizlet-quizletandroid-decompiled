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
public final class AssemblyTextButton extends d {
    public b x;

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public AssemblyTextButton(@NotNull Context context) {
        this(context, null, 6);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    @NotNull
    public final b getVariant() {
        return this.x;
    }

    public final void r() {
        int iOrdinal = this.x.ordinal();
        if (iOrdinal == 0) {
            setBackgroundResource(R.drawable.link_text_button_background);
            ColorStateList colorStateList = getContext().getColorStateList(R.color.assembly_link_text_selector);
            Intrinsics.checkNotNullExpressionValue(colorStateList, "getColorStateList(...)");
            getBinding().d.setTextColor(colorStateList);
            setIconTint(colorStateList);
            return;
        }
        if (iOrdinal == 1) {
            setBackgroundResource(R.drawable.subtle_text_button_background);
            ColorStateList colorStateList2 = getContext().getColorStateList(R.color.assembly_subtle_text_selector);
            Intrinsics.checkNotNullExpressionValue(colorStateList2, "getColorStateList(...)");
            getBinding().d.setTextColor(colorStateList2);
            setIconTint(colorStateList2);
            return;
        }
        if (iOrdinal != 2) {
            throw new NoWhenBranchMatchedException();
        }
        setBackgroundResource(R.drawable.subtle_always_dark_text_button_background);
        ColorStateList colorStateList3 = getContext().getColorStateList(R.color.assembly_subtle_always_dark_text_selector);
        Intrinsics.checkNotNullExpressionValue(colorStateList3, "getColorStateList(...)");
        getBinding().d.setTextColor(colorStateList3);
        setIconTint(colorStateList3);
    }

    public final void setVariant(@NotNull b value) {
        Intrinsics.checkNotNullParameter(value, "value");
        this.x = value;
        r();
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public AssemblyTextButton(@NotNull Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 4);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public AssemblyTextButton(Context context, AttributeSet attributeSet, int i) {
        b bVar = null;
        attributeSet = (i & 2) != 0 ? null : attributeSet;
        Intrinsics.checkNotNullParameter(context, "context");
        super(context, attributeSet);
        this.x = b.c;
        TypedArray typedArrayObtainStyledAttributes = context.obtainStyledAttributes(attributeSet, com.quizlet.assembly.a.h);
        Intrinsics.checkNotNullExpressionValue(typedArrayObtainStyledAttributes, "obtainStyledAttributes(...)");
        int i2 = 0;
        try {
            int i3 = typedArrayObtainStyledAttributes.getInt(0, 2);
            b.b.getClass();
            b[] bVarArrValues = b.values();
            int length = bVarArrValues.length;
            while (true) {
                if (i2 >= length) {
                    break;
                }
                b bVar2 = bVarArrValues[i2];
                if (bVar2.a == i3) {
                    bVar = bVar2;
                    break;
                }
                i2++;
            }
            if (bVar != null) {
                setVariant(bVar);
                typedArrayObtainStyledAttributes.recycle();
                r();
                return;
            }
            throw new IllegalArgumentException("Invalid AssemblyTextButtonVariant");
        } catch (Throwable th) {
            typedArrayObtainStyledAttributes.recycle();
            throw th;
        }
    }
}

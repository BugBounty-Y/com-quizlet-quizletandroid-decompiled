package com.quizlet.assembly.widgets.input;

import android.content.Context;
import android.content.res.Resources;
import android.content.res.TypedArray;
import android.util.AttributeSet;
import com.google.android.material.textfield.TextInputLayout;
import com.quizlet.quizletandroid.R;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class AssemblyInputLayout extends TextInputLayout {
    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public AssemblyInputLayout(@NotNull Context context) {
        this(context, null, 6);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    private final void setVariant(a aVar) {
        int iOrdinal = aVar.ordinal();
        if (iOrdinal != 0) {
            if (iOrdinal != 1) {
                throw new NoWhenBranchMatchedException();
            }
            setHintEnabled(false);
            setExpandedHintEnabled(false);
        }
    }

    @Override // com.google.android.material.textfield.TextInputLayout
    public void setErrorEnabled(boolean z) throws Resources.NotFoundException {
        super.setErrorEnabled(z);
        if (z) {
            CharSequence error = getError();
            if (error == null || StringsKt.O(error)) {
                setError(" ");
            }
        }
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public AssemblyInputLayout(@NotNull Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 4);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public AssemblyInputLayout(Context context, AttributeSet attributeSet, int i) {
        attributeSet = (i & 2) != 0 ? null : attributeSet;
        Intrinsics.checkNotNullParameter(context, "context");
        super(context, attributeSet, R.attr.assemblyTextInputStyle);
        com.quizlet.shared.usecase.studiableMetadata.a aVar = a.b;
        int[] AssemblyInputLayout = com.quizlet.assembly.a.d;
        Intrinsics.checkNotNullExpressionValue(AssemblyInputLayout, "AssemblyInputLayout");
        TypedArray typedArrayObtainStyledAttributes = context.obtainStyledAttributes(attributeSet, AssemblyInputLayout, 0, 0);
        int i2 = typedArrayObtainStyledAttributes.getInt(0, 0);
        a.b.getClass();
        setVariant(com.quizlet.shared.usecase.studiableMetadata.a.h(i2));
        typedArrayObtainStyledAttributes.recycle();
    }
}

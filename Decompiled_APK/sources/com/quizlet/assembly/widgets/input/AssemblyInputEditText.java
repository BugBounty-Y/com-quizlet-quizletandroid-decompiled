package com.quizlet.assembly.widgets.input;

import android.content.Context;
import android.content.res.TypedArray;
import android.util.AttributeSet;
import com.google.android.material.textfield.TextInputEditText;
import com.quizlet.quizletandroid.R;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class AssemblyInputEditText extends TextInputEditText {
    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public AssemblyInputEditText(@NotNull Context context) {
        this(context, null, 6);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    private final void setVariant(a aVar) {
        int iOrdinal = aVar.ordinal();
        if (iOrdinal != 0) {
            if (iOrdinal != 1) {
                throw new NoWhenBranchMatchedException();
            }
            setPadding((int) getResources().getDimension(R.dimen.assembly_input_edit_text_padding_start), (int) getResources().getDimension(R.dimen.assembly_input_edit_text_padding_top), 0, (int) getResources().getDimension(R.dimen.assembly_input_edit_text_padding_bottom));
        }
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public AssemblyInputEditText(@NotNull Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 4);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public AssemblyInputEditText(Context context, AttributeSet attributeSet, int i) {
        attributeSet = (i & 2) != 0 ? null : attributeSet;
        Intrinsics.checkNotNullParameter(context, "context");
        super(context, attributeSet, R.attr.assemblyEditTextStyle);
        com.quizlet.shared.usecase.studiableMetadata.a aVar = a.b;
        int[] AssemblyInputEditText = com.quizlet.assembly.a.c;
        Intrinsics.checkNotNullExpressionValue(AssemblyInputEditText, "AssemblyInputEditText");
        TypedArray typedArrayObtainStyledAttributes = context.obtainStyledAttributes(attributeSet, AssemblyInputEditText, 0, 0);
        int i2 = typedArrayObtainStyledAttributes.getInt(0, 0);
        a.b.getClass();
        setVariant(com.quizlet.shared.usecase.studiableMetadata.a.h(i2));
        typedArrayObtainStyledAttributes.recycle();
    }
}

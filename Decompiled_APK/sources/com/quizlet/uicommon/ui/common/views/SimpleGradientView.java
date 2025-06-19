package com.quizlet.uicommon.ui.common.views;

import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.drawable.GradientDrawable;
import android.util.AttributeSet;
import android.view.View;
import com.quizlet.quizletandroid.ui.common.a;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class SimpleGradientView extends View {
    public final int a;
    public final int b;
    public final int c;

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public SimpleGradientView(@NotNull Context context) {
        this(context, null, 6);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    private final int[] getGradientDrawableColorArray() {
        return new int[]{this.b, this.c};
    }

    private final GradientDrawable.Orientation getGradientDrawableOrientation() {
        return this.a == 0 ? GradientDrawable.Orientation.TOP_BOTTOM : GradientDrawable.Orientation.LEFT_RIGHT;
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public SimpleGradientView(@NotNull Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 4);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public SimpleGradientView(Context context, AttributeSet attributeSet, int i) {
        attributeSet = (i & 2) != 0 ? null : attributeSet;
        Intrinsics.checkNotNullParameter(context, "context");
        super(context, attributeSet, 0);
        if (attributeSet != null) {
            TypedArray typedArrayObtainStyledAttributes = context.getTheme().obtainStyledAttributes(attributeSet, a.e, 0, 0);
            try {
                this.a = typedArrayObtainStyledAttributes.getInteger(1, 0);
                this.b = typedArrayObtainStyledAttributes.getColor(2, 0);
                this.c = typedArrayObtainStyledAttributes.getColor(0, 0);
                GradientDrawable gradientDrawable = new GradientDrawable(getGradientDrawableOrientation(), getGradientDrawableColorArray());
                gradientDrawable.setCornerRadius(DefinitionKt.NO_Float_VALUE);
                setBackground(gradientDrawable);
            } finally {
                typedArrayObtainStyledAttributes.recycle();
            }
        }
    }
}

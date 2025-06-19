package com.skydoves.balloon.vectortext;

import android.content.Context;
import android.content.res.TypedArray;
import android.util.AttributeSet;
import androidx.appcompat.widget.AppCompatTextView;
import com.skydoves.balloon.R;
import com.skydoves.balloon.extensions.TextViewExtensionKt;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class VectorTextView extends AppCompatTextView {
    private VectorTextViewParams drawableTextViewParams;

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public VectorTextView(@NotNull Context context) {
        this(context, null, 2, 0 == true ? 1 : 0);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    private final void initAttrs(Context context, AttributeSet attributeSet) {
        if (attributeSet != null) {
            TypedArray typedArrayObtainStyledAttributes = context.obtainStyledAttributes(attributeSet, R.styleable.VectorTextView);
            Intrinsics.checkNotNullExpressionValue(typedArrayObtainStyledAttributes, "obtainStyledAttributes(...)");
            setDrawableTextViewParams(new VectorTextViewParams(DefinitionKt.takeIfNotNoIntValue(typedArrayObtainStyledAttributes.getResourceId(R.styleable.VectorTextView_balloon_drawableStart, Integer.MIN_VALUE)), DefinitionKt.takeIfNotNoIntValue(typedArrayObtainStyledAttributes.getResourceId(R.styleable.VectorTextView_balloon_drawableEnd, Integer.MIN_VALUE)), DefinitionKt.takeIfNotNoIntValue(typedArrayObtainStyledAttributes.getResourceId(R.styleable.VectorTextView_balloon_drawableBottom, Integer.MIN_VALUE)), DefinitionKt.takeIfNotNoIntValue(typedArrayObtainStyledAttributes.getResourceId(R.styleable.VectorTextView_balloon_drawableTop, Integer.MIN_VALUE)), null, null, null, null, false, null, null, null, null, DefinitionKt.takeIfNotNoIntValue(typedArrayObtainStyledAttributes.getResourceId(R.styleable.VectorTextView_balloon_drawablePadding, Integer.MIN_VALUE)), DefinitionKt.takeIfNotNoIntValue(typedArrayObtainStyledAttributes.getColor(R.styleable.VectorTextView_balloon_drawableTintColor, Integer.MIN_VALUE)), DefinitionKt.takeIfNotNoIntValue(typedArrayObtainStyledAttributes.getResourceId(R.styleable.VectorTextView_balloon_drawableWidth, Integer.MIN_VALUE)), DefinitionKt.takeIfNotNoIntValue(typedArrayObtainStyledAttributes.getResourceId(R.styleable.VectorTextView_balloon_drawableHeight, Integer.MIN_VALUE)), DefinitionKt.takeIfNotNoIntValue(typedArrayObtainStyledAttributes.getResourceId(R.styleable.VectorTextView_balloon_drawableSquareSize, Integer.MIN_VALUE)), 8176, null));
            typedArrayObtainStyledAttributes.recycle();
        }
    }

    public final VectorTextViewParams getDrawableTextViewParams() {
        return this.drawableTextViewParams;
    }

    public final void isRtlSupport(boolean z) {
        VectorTextViewParams vectorTextViewParams = this.drawableTextViewParams;
        if (vectorTextViewParams != null) {
            vectorTextViewParams.setRtlLayout(z);
            TextViewExtensionKt.applyDrawable(this, vectorTextViewParams);
        }
    }

    public final void setDrawableTextViewParams(VectorTextViewParams vectorTextViewParams) {
        if (vectorTextViewParams != null) {
            TextViewExtensionKt.applyDrawable(this, vectorTextViewParams);
        } else {
            vectorTextViewParams = null;
        }
        this.drawableTextViewParams = vectorTextViewParams;
    }

    public /* synthetic */ VectorTextView(Context context, AttributeSet attributeSet, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this(context, (i & 2) != 0 ? null : attributeSet);
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public VectorTextView(@NotNull Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
        Intrinsics.checkNotNullParameter(context, "context");
        initAttrs(context, attributeSet);
    }
}

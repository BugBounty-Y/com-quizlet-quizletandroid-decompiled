package com.quizlet.quizletandroid.ui.common.views;

import android.content.Context;
import android.util.AttributeSet;
import androidx.recyclerview.widget.RecyclerView;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public class VerticalFadingEdgeRecyclerView extends RecyclerView {
    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public VerticalFadingEdgeRecyclerView(@NotNull Context context) {
        this(context, null, 6);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    @Override // android.view.View
    public int getBottomPaddingOffset() {
        if (getClipToPadding()) {
            return 0;
        }
        return getPaddingBottom();
    }

    @Override // android.view.View
    public int getTopPaddingOffset() {
        if (getClipToPadding()) {
            return 0;
        }
        return -getPaddingTop();
    }

    @Override // android.view.View
    public final boolean isPaddingOffsetRequired() {
        return !getClipToPadding();
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public VerticalFadingEdgeRecyclerView(@NotNull Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 4);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public VerticalFadingEdgeRecyclerView(Context context, AttributeSet attributeSet, int i) {
        attributeSet = (i & 2) != 0 ? null : attributeSet;
        Intrinsics.checkNotNullParameter(context, "context");
        super(context, attributeSet, 0);
    }
}

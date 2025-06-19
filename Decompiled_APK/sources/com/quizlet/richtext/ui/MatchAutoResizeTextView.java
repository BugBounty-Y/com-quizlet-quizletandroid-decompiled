package com.quizlet.richtext.ui;

import android.content.Context;
import android.util.AttributeSet;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public class MatchAutoResizeTextView extends d {
    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public MatchAutoResizeTextView(Context context, AttributeSet attributeSet) {
        super(context, attributeSet, 4);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    @Override // com.quizlet.richtext.ui.d
    public final void j() {
        getHelper().getClass();
    }

    public MatchAutoResizeTextView(Context context) {
        super(context);
    }
}

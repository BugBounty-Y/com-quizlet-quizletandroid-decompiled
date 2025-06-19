package com.quizlet.baseui.compose;

import androidx.compose.ui.platform.ComposeView;
import androidx.recyclerview.widget.F0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class c extends F0 {
    public final ComposeView a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(ComposeView itemView) {
        super(itemView);
        Intrinsics.checkNotNullParameter(itemView, "itemView");
        this.a = itemView;
    }
}

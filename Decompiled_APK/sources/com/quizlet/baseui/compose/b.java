package com.quizlet.baseui.compose;

import android.content.Context;
import android.view.ViewGroup;
import androidx.compose.runtime.internal.d;
import androidx.compose.ui.platform.C0972v0;
import androidx.compose.ui.platform.ComposeView;
import androidx.recyclerview.widget.AbstractC1361d0;
import androidx.recyclerview.widget.F0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class b extends AbstractC1361d0 {
    public final d a;

    public b(d content) {
        Intrinsics.checkNotNullParameter(content, "content");
        this.a = content;
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final int getItemCount() {
        return 1;
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final void onBindViewHolder(F0 holder, int i) {
        Intrinsics.checkNotNullParameter(holder, "holder");
        if (holder instanceof c) {
            ((c) holder).a.setContent(new d(true, 695322942, new a(this, 1)));
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final F0 onCreateViewHolder(ViewGroup parent, int i) {
        Intrinsics.checkNotNullParameter(parent, "parent");
        Context context = parent.getContext();
        Intrinsics.checkNotNullExpressionValue(context, "getContext(...)");
        ComposeView composeView = new ComposeView(context, null, 6);
        composeView.setViewCompositionStrategy(C0972v0.b);
        return new c(composeView);
    }
}

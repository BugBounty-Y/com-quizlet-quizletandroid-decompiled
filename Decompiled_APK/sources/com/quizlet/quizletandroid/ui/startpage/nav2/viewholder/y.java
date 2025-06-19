package com.quizlet.quizletandroid.ui.startpage.nav2.viewholder;

import android.view.View;
import androidx.compose.ui.platform.ComposeView;
import com.quizlet.quizletandroid.databinding.Y;
import com.quizlet.quizletandroid.ui.startpage.nav2.model.S;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class y extends com.quizlet.baserecyclerview.c {
    public static final /* synthetic */ int d = 0;

    @Override // com.quizlet.baserecyclerview.c
    public final void c(Object obj) {
        S item = (S) obj;
        Intrinsics.checkNotNullParameter(item, "item");
    }

    @Override // com.quizlet.baserecyclerview.c
    public final androidx.viewbinding.a d() {
        View view = this.a;
        if (view == null) {
            throw new NullPointerException("rootView");
        }
        ComposeView composeView = (ComposeView) view;
        Y y = new Y(composeView, composeView);
        Intrinsics.checkNotNullExpressionValue(y, "bind(...)");
        return y;
    }
}

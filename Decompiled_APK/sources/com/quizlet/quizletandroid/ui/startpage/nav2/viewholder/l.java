package com.quizlet.quizletandroid.ui.startpage.nav2.viewholder;

import android.view.View;
import androidx.compose.ui.platform.ComposeView;
import com.quizlet.data.model.E0;
import com.quizlet.quizletandroid.databinding.V;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class l extends com.quizlet.baserecyclerview.c {
    public static final /* synthetic */ int d = 0;

    @Override // com.quizlet.baserecyclerview.c
    public final void c(Object obj) {
        E0 item = (E0) obj;
        Intrinsics.checkNotNullParameter(item, "item");
    }

    @Override // com.quizlet.baserecyclerview.c
    public final androidx.viewbinding.a d() {
        View view = this.a;
        if (view == null) {
            throw new NullPointerException("rootView");
        }
        ComposeView composeView = (ComposeView) view;
        V v = new V(composeView, composeView);
        Intrinsics.checkNotNullExpressionValue(v, "bind(...)");
        return v;
    }
}

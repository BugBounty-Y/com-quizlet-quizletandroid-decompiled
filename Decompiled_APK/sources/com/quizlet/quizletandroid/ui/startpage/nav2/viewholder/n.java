package com.quizlet.quizletandroid.ui.startpage.nav2.viewholder;

import android.view.View;
import androidx.compose.ui.platform.ComposeView;
import com.quizlet.data.model.D0;
import com.quizlet.quizletandroid.databinding.U;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class n extends com.quizlet.baserecyclerview.c {
    public static final /* synthetic */ int d = 0;

    @Override // com.quizlet.baserecyclerview.c
    public final void c(Object obj) {
        D0 item = (D0) obj;
        Intrinsics.checkNotNullParameter(item, "item");
    }

    @Override // com.quizlet.baserecyclerview.c
    public final androidx.viewbinding.a d() {
        View view = this.a;
        if (view == null) {
            throw new NullPointerException("rootView");
        }
        ComposeView composeView = (ComposeView) view;
        U u = new U(composeView, composeView);
        Intrinsics.checkNotNullExpressionValue(u, "bind(...)");
        return u;
    }
}

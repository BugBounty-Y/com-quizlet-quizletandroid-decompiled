package com.quizlet.quizletandroid.ui.startpage.nav2.viewholder;

import android.view.View;
import androidx.compose.ui.platform.ComposeView;
import com.quizlet.data.model.C0;
import com.quizlet.quizletandroid.databinding.T;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class k extends com.quizlet.baserecyclerview.c {
    public static final /* synthetic */ int d = 0;

    @Override // com.quizlet.baserecyclerview.c
    public final void c(Object obj) {
        C0 item = (C0) obj;
        Intrinsics.checkNotNullParameter(item, "item");
    }

    @Override // com.quizlet.baserecyclerview.c
    public final androidx.viewbinding.a d() {
        View view = this.a;
        if (view == null) {
            throw new NullPointerException("rootView");
        }
        ComposeView composeView = (ComposeView) view;
        T t = new T(composeView, composeView);
        Intrinsics.checkNotNullExpressionValue(t, "bind(...)");
        return t;
    }
}

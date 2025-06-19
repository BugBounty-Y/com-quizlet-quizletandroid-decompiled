package com.quizlet.quizletandroid.ui.startpage.nav2.viewholder;

import android.view.View;
import android.widget.FrameLayout;
import com.quizlet.quizletandroid.databinding.I;
import com.quizlet.quizletandroid.ui.startpage.nav2.model.J;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class q extends com.quizlet.baserecyclerview.c {
    public static final /* synthetic */ int d = 0;

    @Override // com.quizlet.baserecyclerview.c
    public final void c(Object obj) {
        J item = (J) obj;
        Intrinsics.checkNotNullParameter(item, "item");
    }

    @Override // com.quizlet.baserecyclerview.c
    public final androidx.viewbinding.a d() {
        View view = this.a;
        if (view == null) {
            throw new NullPointerException("rootView");
        }
        I i = new I((FrameLayout) view);
        Intrinsics.checkNotNullExpressionValue(i, "bind(...)");
        return i;
    }
}

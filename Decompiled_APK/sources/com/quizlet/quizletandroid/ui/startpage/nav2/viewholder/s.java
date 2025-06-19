package com.quizlet.quizletandroid.ui.startpage.nav2.viewholder;

import android.view.View;
import androidx.compose.ui.platform.ComposeView;
import com.quizlet.quizletandroid.databinding.Z;
import com.quizlet.quizletandroid.ui.common.ads.G;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class s extends com.quizlet.baserecyclerview.c {
    public static final /* synthetic */ int e = 0;
    public final G d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public s(View itemView, G onClick) {
        super(itemView);
        Intrinsics.checkNotNullParameter(itemView, "itemView");
        Intrinsics.checkNotNullParameter(onClick, "onClick");
        this.d = onClick;
    }

    @Override // com.quizlet.baserecyclerview.c
    public final androidx.viewbinding.a d() {
        View view = this.a;
        if (view == null) {
            throw new NullPointerException("rootView");
        }
        ComposeView composeView = (ComposeView) view;
        Z z = new Z(composeView, composeView);
        Intrinsics.checkNotNullExpressionValue(z, "bind(...)");
        return z;
    }

    @Override // com.quizlet.baserecyclerview.c
    /* renamed from: f, reason: merged with bridge method [inline-methods] */
    public final void c(com.quizlet.ui.models.content.carditem.d item) {
        Intrinsics.checkNotNullParameter(item, "item");
        ((Z) e()).b.setContent(new androidx.compose.runtime.internal.d(true, 441686586, new r(item, this, 1)));
    }
}

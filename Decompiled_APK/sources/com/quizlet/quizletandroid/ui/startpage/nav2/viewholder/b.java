package com.quizlet.quizletandroid.ui.startpage.nav2.viewholder;

import android.content.Context;
import android.view.View;
import androidx.compose.ui.platform.ComposeView;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3205m5;
import com.quizlet.quizletandroid.databinding.S;
import com.quizlet.quizletandroid.ui.startpage.nav2.model.C4705a;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b extends com.quizlet.baserecyclerview.c {
    public static final /* synthetic */ int e = 0;
    public final com.quizlet.login.magiclink.ui.e d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(View itemView, com.quizlet.login.magiclink.ui.e onClick) {
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
        S s = new S(composeView, composeView);
        Intrinsics.checkNotNullExpressionValue(s, "bind(...)");
        return s;
    }

    @Override // com.quizlet.baserecyclerview.c
    /* renamed from: f, reason: merged with bridge method [inline-methods] */
    public final void c(C4705a item) {
        Intrinsics.checkNotNullParameter(item, "item");
        Context context = this.b;
        Intrinsics.checkNotNullExpressionValue(context, "<get-context>(...)");
        ((S) e()).b.setContent(new androidx.compose.runtime.internal.d(true, -56169852, new a(AbstractC3205m5.e(context), item, this, 1)));
    }
}

package com.quizlet.quizletandroid.ui.group.classcontent.adapter;

import android.view.View;
import com.quizlet.features.infra.legacyadapter.viewholder.h;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d extends f {
    public static final /* synthetic */ int b = 0;
    public final h a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(View view) {
        super(view);
        Intrinsics.checkNotNullParameter(view, "itemView");
        Intrinsics.checkNotNullParameter(view, "view");
        this.a = new h(view);
    }
}

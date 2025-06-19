package com.quizlet.quizletandroid.ui.group.classcontent.adapter;

import android.view.View;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c extends f {
    public static final /* synthetic */ int c = 0;
    public final com.quizlet.features.infra.legacyadapter.viewholder.e a;
    public com.quizlet.quizletandroid.ui.group.classcontent.models.c b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(View itemView, com.quizlet.quizletandroid.ui.group.classcontent.viewmodel.a clickListener) {
        super(itemView);
        Intrinsics.checkNotNullParameter(itemView, "itemView");
        Intrinsics.checkNotNullParameter(clickListener, "clickListener");
        com.quizlet.features.infra.legacyadapter.viewholder.e eVar = new com.quizlet.features.infra.legacyadapter.viewholder.e(itemView);
        this.a = eVar;
        eVar.a(new com.braze.ui.inappmessage.views.a(22, clickListener, this));
        eVar.b(new b(0, clickListener, this));
    }
}

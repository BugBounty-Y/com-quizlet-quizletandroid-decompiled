package com.quizlet.quizletandroid.ui.group.classcontent.adapter;

import android.view.View;
import com.quizlet.features.infra.legacyadapter.viewholder.k;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e extends f {
    public static final /* synthetic */ int c = 0;
    public final k a;
    public com.quizlet.quizletandroid.ui.group.classcontent.models.d b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(View itemView, com.quizlet.quizletandroid.ui.group.classcontent.viewmodel.a clickListener) {
        super(itemView);
        Intrinsics.checkNotNullParameter(itemView, "itemView");
        Intrinsics.checkNotNullParameter(clickListener, "clickListener");
        k kVar = new k(itemView);
        this.a = kVar;
        kVar.a(new com.braze.ui.inappmessage.views.a(23, clickListener, this));
        kVar.b(new b(1, clickListener, this));
    }
}

package com.quizlet.quizletandroid.ui.common.adapter.viewholder;

import android.view.View;
import androidx.recyclerview.widget.F0;
import com.google.android.gms.internal.mlkit_vision_barcode.K6;
import kotlin.jvm.internal.Intrinsics;
import kotlin.u;

/* loaded from: classes3.dex */
public final class b extends F0 {
    public static final /* synthetic */ int d = 0;
    public final com.quizlet.qutils.image.loading.a a;
    public final com.quizlet.infra.legacysyncengine.managers.d b;
    public final u c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(View itemView) {
        super(itemView);
        Intrinsics.checkNotNullParameter(itemView, "itemView");
        this.c = kotlin.l.b(new com.quizlet.features.infra.legacyadapter.viewholder.a(itemView, 2));
        com.quizlet.quizletandroid.u uVar = (com.quizlet.quizletandroid.u) ((com.quizlet.quizletandroid.injection.components.a) K6.b(com.quizlet.quizletandroid.injection.components.a.class, itemView.getContext().getApplicationContext()));
        this.a = (com.quizlet.qutils.image.loading.a) uVar.s.get();
        this.b = (com.quizlet.infra.legacysyncengine.managers.d) uVar.Z.get();
    }

    public final int c(int i) {
        return this.itemView.getResources().getDimensionPixelSize(i);
    }
}

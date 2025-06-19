package com.quizlet.quizletandroid.ui.startpage.nav2.viewholder;

import androidx.recyclerview.widget.RecyclerView;
import com.google.android.gms.internal.mlkit_vision_document_scanner.X5;
import com.quizlet.quizletandroid.ui.startpage.nav2.Y;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class h implements io.reactivex.rxjava3.functions.d {
    public final /* synthetic */ RecyclerView a;
    public final /* synthetic */ Y b;
    public final /* synthetic */ com.quizlet.quizletandroid.ui.startpage.nav2.model.u c;
    public final /* synthetic */ int d;

    public h(RecyclerView recyclerView, Y y, com.quizlet.quizletandroid.ui.startpage.nav2.model.u uVar, int i) {
        this.a = recyclerView;
        this.b = y;
        this.c = uVar;
        this.d = i;
    }

    @Override // io.reactivex.rxjava3.functions.d
    public final void accept(Object obj) {
        Integer it2 = (Integer) obj;
        Intrinsics.checkNotNullParameter(it2, "it");
        X5.b(this.a, this.b, true, this.c, this.d);
    }
}

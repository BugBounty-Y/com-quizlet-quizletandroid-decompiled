package com.quizlet.search.composables;

import com.quizlet.data.model.Y;
import kotlin.jvm.functions.Function0;

/* loaded from: classes3.dex */
public final /* synthetic */ class J implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ com.quizlet.search.viewmodels.D b;
    public final /* synthetic */ String c;

    public /* synthetic */ J(com.quizlet.search.viewmodels.D d, String str, int i) {
        this.a = i;
        this.b = d;
        this.c = str;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return this.b.C(this.c);
            default:
                com.quizlet.search.viewmodels.D d = this.b;
                return new com.quizlet.search.paging.d(d.h, this.c, kotlin.collections.A.b(Y.TEXTBOOK), d.j, d);
        }
    }
}

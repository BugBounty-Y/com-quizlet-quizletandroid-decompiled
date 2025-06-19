package com.quizlet.edgy.ui.recyclerview.viewholder;

import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class d extends com.quizlet.baserecyclerview.c {
    @Override // com.quizlet.baserecyclerview.c
    public final void c(Object obj) {
        Unit item = (Unit) obj;
        Intrinsics.checkNotNullParameter(item, "item");
    }

    @Override // com.quizlet.baserecyclerview.c
    public final androidx.viewbinding.a d() {
        com.quizlet.edgy.databinding.e eVarA = com.quizlet.edgy.databinding.e.a(this.a);
        Intrinsics.checkNotNullExpressionValue(eVarA, "bind(...)");
        return eVarA;
    }
}

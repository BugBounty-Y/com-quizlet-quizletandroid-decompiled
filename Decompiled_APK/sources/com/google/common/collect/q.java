package com.google.common.collect;

import java.util.Iterator;

/* loaded from: classes2.dex */
public final class q extends F {
    public final /* synthetic */ com.quizlet.baserecyclerview.decoration.a b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public q(Iterator it2, com.quizlet.baserecyclerview.decoration.a aVar) {
        super(it2);
        this.b = aVar;
    }

    @Override // com.google.common.collect.F
    public final Object a(Object obj) {
        return this.b.apply(obj);
    }
}

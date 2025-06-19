package com.quizlet.features.questiontypes.grading;

import androidx.work.impl.model.l;
import com.quizlet.studiablemodels.grading.WrittenResponse;
import kotlin.coroutines.jvm.internal.c;

/* loaded from: classes3.dex */
public final class b extends c {
    public l j;
    public WrittenResponse k;
    public /* synthetic */ Object l;
    public final /* synthetic */ l m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(l lVar, c cVar) {
        super(cVar);
        this.m = lVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        return this.m.k(null, this);
    }
}

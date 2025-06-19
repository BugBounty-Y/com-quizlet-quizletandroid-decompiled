package com.quizlet.features.questiontypes.truefalse.usecases;

import com.quizlet.data.repository.set.f;
import com.quizlet.studiablemodels.grading.TrueFalseResponse;
import kotlin.coroutines.jvm.internal.c;

/* loaded from: classes3.dex */
public final class a extends c {
    public f j;
    public TrueFalseResponse k;
    public boolean l;
    public /* synthetic */ Object m;
    public final /* synthetic */ f n;
    public int o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(f fVar, c cVar) {
        super(cVar);
        this.n = fVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.m = obj;
        this.o |= Integer.MIN_VALUE;
        return this.n.o(null, null, false, this);
    }
}

package com.quizlet.featuregate.features.studymodes;

import com.quizlet.data.repository.set.f;
import com.quizlet.generated.enums.H;
import com.quizlet.generated.enums.J;
import kotlin.coroutines.jvm.internal.c;

/* loaded from: classes2.dex */
public final class b extends c {
    public f j;
    public J k;
    public H l;
    public /* synthetic */ Object m;
    public final /* synthetic */ f n;
    public int o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(f fVar, c cVar) {
        super(cVar);
        this.n = fVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.m = obj;
        this.o |= Integer.MIN_VALUE;
        return this.n.r(this);
    }
}

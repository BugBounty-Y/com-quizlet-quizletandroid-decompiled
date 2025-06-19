package com.quizlet.featuregate.features.learn;

import com.quizlet.data.repository.folderwithcreator.e;
import kotlin.coroutines.jvm.internal.c;

/* loaded from: classes2.dex */
public final class a extends c {
    public e j;
    public /* synthetic */ Object k;
    public final /* synthetic */ e l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(e eVar, c cVar) {
        super(cVar);
        this.l = eVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return this.l.j(this);
    }
}

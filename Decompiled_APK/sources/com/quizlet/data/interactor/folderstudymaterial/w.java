package com.quizlet.data.interactor.folderstudymaterial;

import java.util.List;

/* loaded from: classes2.dex */
public final class w extends kotlin.coroutines.jvm.internal.c {
    public Object j;
    public List k;
    public Object l;
    public /* synthetic */ Object m;
    public final /* synthetic */ z n;
    public int o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public w(z zVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.n = zVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.m = obj;
        this.o |= Integer.MIN_VALUE;
        Object objA = this.n.a(null, null, this);
        return objA == kotlin.coroutines.intrinsics.a.a ? objA : new kotlin.r(objA);
    }
}

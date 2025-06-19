package com.quizlet.features.folders.addtofolder.viewmodel.usecase;

import com.google.firebase.messaging.p;
import java.util.List;

/* loaded from: classes3.dex */
public final class d extends kotlin.coroutines.jvm.internal.c {
    public List j;
    public /* synthetic */ Object k;
    public final /* synthetic */ p l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(p pVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = pVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return this.l.s(null, this);
    }
}

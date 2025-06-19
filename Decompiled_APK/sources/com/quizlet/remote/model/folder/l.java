package com.quizlet.remote.model.folder;

import com.quizlet.data.model.C4168t1;
import java.io.Serializable;
import java.util.List;

/* loaded from: classes3.dex */
public final class l extends kotlin.coroutines.jvm.internal.c {
    public p j;
    public /* synthetic */ Object k;
    public final /* synthetic */ p l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public l(p pVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = pVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        Serializable serializableD = this.l.d(0L, this);
        return serializableD == kotlin.coroutines.intrinsics.a.a ? serializableD : new C4168t1((List) serializableD);
    }
}

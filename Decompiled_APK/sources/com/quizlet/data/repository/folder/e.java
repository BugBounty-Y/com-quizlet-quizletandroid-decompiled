package com.quizlet.data.repository.folder;

import com.quizlet.data.model.C4168t1;
import java.util.List;

/* loaded from: classes2.dex */
public final class e extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public final /* synthetic */ i k;
    public int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(i iVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.k = iVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.l |= Integer.MIN_VALUE;
        Object objD = this.k.d(0L, this);
        return objD == kotlin.coroutines.intrinsics.a.a ? objD : new C4168t1((List) objD);
    }
}

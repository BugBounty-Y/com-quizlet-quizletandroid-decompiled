package com.quizlet.data.interactor.folderstudymaterial;

import com.quizlet.data.model.C4168t1;
import java.util.List;

/* loaded from: classes2.dex */
public final class i extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public final /* synthetic */ com.quizlet.data.interactor.folder.c k;
    public int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public i(com.quizlet.data.interactor.folder.c cVar, kotlin.coroutines.jvm.internal.c cVar2) {
        super(cVar2);
        this.k = cVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.l |= Integer.MIN_VALUE;
        Object objA = this.k.a(0L, this);
        return objA == kotlin.coroutines.intrinsics.a.a ? objA : new C4168t1((List) objA);
    }
}

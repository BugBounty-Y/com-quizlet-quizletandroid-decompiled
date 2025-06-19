package com.quizlet.data.interactor.folderstudymaterial;

/* loaded from: classes2.dex */
public final class b extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public final /* synthetic */ com.google.firebase.crashlytics.internal.settings.b k;
    public int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(com.google.firebase.crashlytics.internal.settings.b bVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.k = bVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.l |= Integer.MIN_VALUE;
        Object objC = this.k.c(null, this);
        return objC == kotlin.coroutines.intrinsics.a.a ? objC : new kotlin.r(objC);
    }
}

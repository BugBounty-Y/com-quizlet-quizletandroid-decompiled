package com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase;

import java.io.Serializable;
import kotlin.r;

/* loaded from: classes3.dex */
public final class k extends kotlin.coroutines.jvm.internal.c {
    public String j;
    public /* synthetic */ Object k;
    public final /* synthetic */ com.google.firebase.crashlytics.internal.common.j l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public k(com.google.firebase.crashlytics.internal.common.j jVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = jVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws EmptyQueryException {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        Serializable serializableF = this.l.f(null, this);
        return serializableF == kotlin.coroutines.intrinsics.a.a ? serializableF : new r(serializableF);
    }
}

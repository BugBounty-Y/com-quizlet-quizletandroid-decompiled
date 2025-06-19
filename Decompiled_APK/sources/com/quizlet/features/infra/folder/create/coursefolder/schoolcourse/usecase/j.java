package com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase;

import com.google.firebase.messaging.p;
import java.io.Serializable;
import kotlin.r;

/* loaded from: classes3.dex */
public final class j extends kotlin.coroutines.jvm.internal.c {
    public String j;
    public /* synthetic */ Object k;
    public final /* synthetic */ p l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public j(p pVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = pVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        Serializable serializableX = this.l.x(null, this);
        return serializableX == kotlin.coroutines.intrinsics.a.a ? serializableX : new r(serializableX);
    }
}

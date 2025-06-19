package com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase;

import com.onetrust.otpublishers.headless.UI.fragment.q;
import kotlin.r;

/* loaded from: classes3.dex */
public final class a extends kotlin.coroutines.jvm.internal.c {
    public com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.c j;
    public /* synthetic */ Object k;
    public final /* synthetic */ q l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(q qVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = qVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        Object objS = this.l.s(null, this);
        return objS == kotlin.coroutines.intrinsics.a.a ? objS : new r(objS);
    }
}

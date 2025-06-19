package com.quizlet.features.subjects.usecase;

import com.onetrust.otpublishers.headless.UI.fragment.q;
import com.quizlet.generated.enums.I1;

/* loaded from: classes3.dex */
public final class a extends kotlin.coroutines.jvm.internal.c {
    public I1 j;
    public /* synthetic */ Object k;
    public final /* synthetic */ q l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(q qVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = qVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return this.l.g(null, this);
    }
}

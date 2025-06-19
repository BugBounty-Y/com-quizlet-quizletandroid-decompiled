package com.quizlet.quizletandroid.ui.studymodes.assistant.settings.interaction;

import com.google.android.gms.measurement.internal.J;
import com.quizlet.generated.enums.P;

/* loaded from: classes3.dex */
public final class c extends kotlin.coroutines.jvm.internal.c {
    public J j;
    public com.quizlet.data.interactor.metering.b k;
    public Long l;
    public P m;
    public long n;
    public /* synthetic */ Object o;
    public final /* synthetic */ J p;
    public int q;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(J j, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.p = j;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.o = obj;
        this.q |= Integer.MIN_VALUE;
        return this.p.e(0L, this);
    }
}

package com.quizlet.login.common.interactors;

/* loaded from: classes3.dex */
public final class w extends kotlin.coroutines.jvm.internal.c {
    public com.onetrust.otpublishers.headless.UI.TVUI.datautils.d j;
    public String k;
    public Object l;
    public boolean m;
    public /* synthetic */ Object n;
    public final /* synthetic */ com.onetrust.otpublishers.headless.UI.TVUI.datautils.d o;
    public int p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public w(com.onetrust.otpublishers.headless.UI.TVUI.datautils.d dVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.o = dVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.n = obj;
        this.p |= Integer.MIN_VALUE;
        return this.o.k(null, null, 0L, false, this);
    }
}

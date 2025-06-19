package com.quizlet.quizletandroid.ui.startpage.nav2.usecases;

import java.util.ArrayList;
import java.util.List;

/* loaded from: classes3.dex */
public final class g extends kotlin.coroutines.jvm.internal.c {
    public Object j;
    public List k;
    public ArrayList l;
    public long m;
    public /* synthetic */ Object n;
    public final /* synthetic */ k o;
    public int p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public g(k kVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.o = kVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.n = obj;
        this.p |= Integer.MIN_VALUE;
        return this.o.e(this);
    }
}

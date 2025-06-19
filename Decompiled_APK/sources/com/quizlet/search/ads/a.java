package com.quizlet.search.ads;

import com.quizlet.data.repository.achievements.h;
import java.util.List;

/* loaded from: classes3.dex */
public final class a extends kotlin.coroutines.jvm.internal.c {
    public h j;
    public List k;
    public int l;
    public /* synthetic */ Object m;
    public final /* synthetic */ h n;
    public int o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(h hVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.n = hVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.m = obj;
        this.o |= Integer.MIN_VALUE;
        return this.n.f(0, null, this);
    }
}

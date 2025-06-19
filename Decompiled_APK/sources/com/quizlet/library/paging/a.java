package com.quizlet.library.paging;

import java.util.ArrayList;
import kotlin.coroutines.jvm.internal.c;

/* loaded from: classes3.dex */
public final class a extends c {
    public b j;
    public ArrayList k;
    public int l;
    public /* synthetic */ Object m;
    public final /* synthetic */ b n;
    public int o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(b bVar, c cVar) {
        super(cVar);
        this.n = bVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.m = obj;
        this.o |= Integer.MIN_VALUE;
        return this.n.c(null, this);
    }
}

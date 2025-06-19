package com.quizlet.upgrade.data;

import java.util.Iterator;
import kotlin.jvm.functions.Function2;

/* renamed from: com.quizlet.upgrade.data.f, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4838f extends kotlin.coroutines.jvm.internal.c {
    public com.quizlet.data.repository.user.a j;
    public Function2 k;
    public Iterator l;
    public boolean m;
    public /* synthetic */ Object n;
    public final /* synthetic */ com.quizlet.data.repository.user.a o;
    public int p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4838f(com.quizlet.data.repository.user.a aVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.o = aVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.n = obj;
        this.p |= Integer.MIN_VALUE;
        return com.quizlet.data.repository.user.a.d(this.o, false, null, this);
    }
}

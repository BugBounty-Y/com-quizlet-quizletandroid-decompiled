package test.utils;

import java.util.ArrayList;
import java.util.List;

/* loaded from: classes3.dex */
public final class h extends kotlin.coroutines.jvm.internal.c {
    public com.quizlet.local.ormlite.models.term.b j;
    public List k;
    public ArrayList l;
    public /* synthetic */ Object m;
    public final /* synthetic */ com.quizlet.local.ormlite.models.term.b n;
    public int o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public h(com.quizlet.local.ormlite.models.term.b bVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.n = bVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.m = obj;
        this.o |= Integer.MIN_VALUE;
        return this.n.g(null, null, this);
    }
}

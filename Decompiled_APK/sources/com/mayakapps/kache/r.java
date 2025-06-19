package com.mayakapps.kache;

import java.util.LinkedHashMap;
import java.util.Map;

/* loaded from: classes2.dex */
public final class r extends kotlin.coroutines.jvm.internal.c {
    public u j;
    public Map k;
    public LinkedHashMap l;
    public kotlinx.coroutines.sync.c m;
    public /* synthetic */ Object n;
    public final /* synthetic */ u o;
    public int p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public r(u uVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.o = uVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.n = obj;
        this.p |= Integer.MIN_VALUE;
        return this.o.l(null, this);
    }
}

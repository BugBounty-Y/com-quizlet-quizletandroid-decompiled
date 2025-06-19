package androidx.compose.foundation.pager;

import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes.dex */
public final class J extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public final /* synthetic */ K k;
    public int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public J(K k, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.k = k;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.l |= Integer.MIN_VALUE;
        return this.k.a(null, DefinitionKt.NO_Float_VALUE, this);
    }
}

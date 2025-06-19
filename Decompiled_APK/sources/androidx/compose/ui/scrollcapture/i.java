package androidx.compose.ui.scrollcapture;

import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes.dex */
public final class i extends kotlin.coroutines.jvm.internal.c {
    public j j;
    public /* synthetic */ Object k;
    public final /* synthetic */ j l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public i(j jVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = jVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return this.l.b(DefinitionKt.NO_Float_VALUE, this);
    }
}

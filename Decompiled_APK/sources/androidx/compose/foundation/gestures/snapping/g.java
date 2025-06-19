package androidx.compose.foundation.gestures.snapping;

import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes.dex */
public final class g extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public final /* synthetic */ h k;
    public int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public g(h hVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.k = hVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.l |= Integer.MIN_VALUE;
        return h.b(this.k, null, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, null, this);
    }
}

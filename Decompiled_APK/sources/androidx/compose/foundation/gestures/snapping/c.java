package androidx.compose.foundation.gestures.snapping;

import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class c extends kotlin.coroutines.jvm.internal.c {
    public Function1 j;
    public /* synthetic */ Object k;
    public final /* synthetic */ h l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(h hVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = hVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return this.l.c(null, DefinitionKt.NO_Float_VALUE, null, this);
    }
}

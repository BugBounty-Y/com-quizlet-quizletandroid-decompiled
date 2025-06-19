package androidx.compose.ui.input.pointer;

import kotlinx.coroutines.y0;

/* loaded from: classes.dex */
public final class w extends kotlin.coroutines.jvm.internal.c {
    public y0 j;
    public /* synthetic */ Object k;
    public final /* synthetic */ z l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public w(z zVar, kotlin.coroutines.jvm.internal.a aVar) {
        super(aVar);
        this.l = zVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return this.l.f(0L, null, this);
    }
}

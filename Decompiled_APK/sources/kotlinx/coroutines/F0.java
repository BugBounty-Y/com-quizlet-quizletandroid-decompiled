package kotlinx.coroutines;

import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class F0 extends kotlin.coroutines.jvm.internal.c {
    public Function2 j;
    public kotlin.jvm.internal.J k;
    public /* synthetic */ Object l;
    public int m;

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.m |= Integer.MIN_VALUE;
        return E.L(0L, null, this);
    }
}

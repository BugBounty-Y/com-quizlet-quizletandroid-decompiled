package androidx.compose.foundation.gestures;

import kotlin.InterfaceC4938g;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final class m1 extends kotlin.coroutines.jvm.internal.c {
    public o1 j;
    public InterfaceC4938g k;
    public Function0 l;
    public float m;
    public /* synthetic */ Object n;
    public final /* synthetic */ o1 o;
    public int p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public m1(o1 o1Var, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.o = o1Var;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.n = obj;
        this.p |= Integer.MIN_VALUE;
        return this.o.a(null, null, this);
    }
}

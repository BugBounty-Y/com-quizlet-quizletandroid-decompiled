package kotlinx.coroutines;

/* loaded from: classes3.dex */
public final class K extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public int k;

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.k |= Integer.MIN_VALUE;
        E.g(this);
        return kotlin.coroutines.intrinsics.a.a;
    }
}

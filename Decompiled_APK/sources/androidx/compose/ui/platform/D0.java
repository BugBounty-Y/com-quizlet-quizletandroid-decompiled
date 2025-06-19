package androidx.compose.ui.platform;

/* loaded from: classes.dex */
public final class D0 extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public int k;

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.k |= Integer.MIN_VALUE;
        F0.a(null, null, this);
        return kotlin.coroutines.intrinsics.a.a;
    }
}

package androidx.paging;

import androidx.compose.foundation.text.input.internal.C0496b;

/* renamed from: androidx.paging.f0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1314f0 extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public final /* synthetic */ C0496b k;
    public int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1314f0(C0496b c0496b, kotlin.coroutines.h hVar) {
        super(hVar);
        this.k = c0496b;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.l |= Integer.MIN_VALUE;
        return this.k.a(null, this);
    }
}

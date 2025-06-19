package kotlinx.coroutines.flow;

import androidx.datastore.core.C1087t;

/* renamed from: kotlinx.coroutines.flow.a, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4984a extends kotlin.coroutines.jvm.internal.c {
    public kotlinx.coroutines.flow.internal.C j;
    public /* synthetic */ Object k;
    public final /* synthetic */ C1087t l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4984a(C1087t c1087t, kotlin.coroutines.h hVar) {
        super(hVar);
        this.l = c1087t;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return this.l.b(null, this);
    }
}

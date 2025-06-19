package androidx.paging;

import androidx.compose.foundation.text.input.internal.C0496b;
import kotlin.collections.IndexedValue;

/* renamed from: androidx.paging.e, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1311e extends kotlin.coroutines.jvm.internal.c {
    public C0496b j;
    public IndexedValue k;
    public /* synthetic */ Object l;
    public final /* synthetic */ C0496b m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1311e(C0496b c0496b, kotlin.coroutines.h hVar) {
        super(hVar);
        this.m = c0496b;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        return this.m.b(null, this);
    }
}

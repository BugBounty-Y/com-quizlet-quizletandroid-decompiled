package kotlinx.coroutines.flow;

import androidx.compose.animation.C0297y;

/* renamed from: kotlinx.coroutines.flow.f, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4989f extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public final /* synthetic */ C0297y k;
    public int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4989f(C0297y c0297y, kotlin.coroutines.h hVar) {
        super(hVar);
        this.k = c0297y;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.l |= Integer.MIN_VALUE;
        return this.k.emit(null, this);
    }
}

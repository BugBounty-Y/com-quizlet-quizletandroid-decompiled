package kotlinx.coroutines.flow;

import androidx.compose.foundation.text.C0494i0;

/* renamed from: kotlinx.coroutines.flow.z, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C5017z extends kotlin.coroutines.jvm.internal.c {
    public C0494i0 j;
    public /* synthetic */ Object k;
    public final /* synthetic */ C0494i0 l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C5017z(C0494i0 c0494i0, kotlin.coroutines.h hVar) {
        super(hVar);
        this.l = c0494i0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return this.l.emit(null, this);
    }
}

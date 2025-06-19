package kotlinx.coroutines.sync;

import java.util.concurrent.atomic.AtomicReferenceArray;
import kotlin.coroutines.CoroutineContext;
import kotlinx.coroutines.internal.q;

/* loaded from: classes3.dex */
public final class k extends q {
    public final /* synthetic */ AtomicReferenceArray e;

    public k(long j, k kVar, int i) {
        super(j, kVar, i);
        this.e = new AtomicReferenceArray(j.f);
    }

    @Override // kotlinx.coroutines.internal.q
    public final int g() {
        return j.f;
    }

    @Override // kotlinx.coroutines.internal.q
    public final void h(int i, CoroutineContext coroutineContext) {
        this.e.set(i, j.e);
        i();
    }

    public final String toString() {
        return "SemaphoreSegment[id=" + this.c + ", hashCode=" + hashCode() + ']';
    }
}

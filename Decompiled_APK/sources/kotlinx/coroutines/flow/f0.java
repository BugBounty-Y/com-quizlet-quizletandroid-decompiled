package kotlinx.coroutines.flow;

import kotlinx.coroutines.C5028l;
import kotlinx.coroutines.flow.internal.AbstractC4993a;
import kotlinx.coroutines.flow.internal.AbstractC4995c;

/* loaded from: classes3.dex */
public final class f0 extends AbstractC4995c {
    public long a;
    public C5028l b;

    @Override // kotlinx.coroutines.flow.internal.AbstractC4995c
    public final boolean a(AbstractC4993a abstractC4993a) {
        d0 d0Var = (d0) abstractC4993a;
        if (this.a >= 0) {
            return false;
        }
        long j = d0Var.i;
        if (j < d0Var.j) {
            d0Var.j = j;
        }
        this.a = j;
        return true;
    }

    @Override // kotlinx.coroutines.flow.internal.AbstractC4995c
    public final kotlin.coroutines.h[] b(AbstractC4993a abstractC4993a) {
        long j = this.a;
        this.a = -1L;
        this.b = null;
        return ((d0) abstractC4993a).w(j);
    }
}

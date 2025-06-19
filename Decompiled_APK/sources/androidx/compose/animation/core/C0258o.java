package androidx.compose.animation.core;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.W0;

/* renamed from: androidx.compose.animation.core.o, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0258o implements W0 {
    public final L0 a;
    public final InterfaceC0773a0 b;
    public AbstractC0267t c;
    public long d;
    public long e;
    public boolean f;

    public /* synthetic */ C0258o(L0 l0, Object obj, AbstractC0267t abstractC0267t, int i) {
        this(l0, obj, (i & 4) != 0 ? null : abstractC0267t, Long.MIN_VALUE, Long.MIN_VALUE, false);
    }

    public final Object a() {
        return this.a.b.invoke(this.c);
    }

    @Override // androidx.compose.runtime.W0
    public final Object getValue() {
        return ((androidx.compose.runtime.L0) this.b).getValue();
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("AnimationState(value=");
        sb.append(((androidx.compose.runtime.L0) this.b).getValue());
        sb.append(", velocity=");
        sb.append(a());
        sb.append(", isRunning=");
        sb.append(this.f);
        sb.append(", lastFrameTimeNanos=");
        sb.append(this.d);
        sb.append(", finishedTimeNanos=");
        return androidx.compose.animation.d0.q(sb, this.e, ')');
    }

    public C0258o(L0 l0, Object obj, AbstractC0267t abstractC0267t, long j, long j2, boolean z) {
        AbstractC0267t abstractC0267tK;
        this.a = l0;
        this.b = C0776c.z(obj);
        if (abstractC0267t != null) {
            abstractC0267tK = AbstractC0240f.k(abstractC0267t);
        } else {
            abstractC0267tK = (AbstractC0267t) l0.a.invoke(obj);
            abstractC0267tK.d();
        }
        this.c = abstractC0267tK;
        this.d = j;
        this.e = j2;
        this.f = z;
    }
}

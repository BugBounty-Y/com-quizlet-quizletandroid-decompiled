package kotlinx.coroutines;

import kotlin.collections.C4927s;

/* loaded from: classes3.dex */
public abstract class Z extends AbstractC5040y {
    public static final /* synthetic */ int e = 0;
    public long b;
    public boolean c;
    public C4927s d;

    @Override // kotlinx.coroutines.AbstractC5040y
    public final AbstractC5040y c0(int i) {
        kotlinx.coroutines.internal.b.a(i);
        return this;
    }

    public final void k0(boolean z) {
        long j = this.b - (z ? 4294967296L : 1L);
        this.b = j;
        if (j <= 0 && this.c) {
            shutdown();
        }
    }

    public final void l0(M m) {
        C4927s c4927s = this.d;
        if (c4927s == null) {
            c4927s = new C4927s();
            this.d = c4927s;
        }
        c4927s.addLast(m);
    }

    public abstract Thread m0();

    public final void n0(boolean z) {
        this.b = (z ? 4294967296L : 1L) + this.b;
        if (z) {
            return;
        }
        this.c = true;
    }

    public abstract long o0();

    public final boolean p0() {
        C4927s c4927s = this.d;
        if (c4927s == null) {
            return false;
        }
        M m = (M) (c4927s.isEmpty() ? null : c4927s.removeFirst());
        if (m == null) {
            return false;
        }
        m.run();
        return true;
    }

    public void q0(long j, W w) {
        F.i.v0(j, w);
    }

    public abstract void shutdown();
}

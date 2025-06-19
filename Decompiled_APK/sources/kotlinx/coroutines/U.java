package kotlinx.coroutines;

import kotlin.Unit;

/* loaded from: classes3.dex */
public final class U extends W {
    public final C5028l c;
    public final /* synthetic */ Y d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public U(Y y, long j, C5028l c5028l) {
        super(j);
        this.d = y;
        this.c = c5028l;
    }

    @Override // java.lang.Runnable
    public final void run() throws DispatchException {
        this.c.E(this.d, Unit.a);
    }

    @Override // kotlinx.coroutines.W
    public final String toString() {
        return super.toString() + this.c;
    }
}

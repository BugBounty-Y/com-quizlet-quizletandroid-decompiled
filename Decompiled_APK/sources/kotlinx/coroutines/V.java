package kotlinx.coroutines;

/* loaded from: classes3.dex */
public final class V extends W {
    public final Runnable c;

    public V(long j, Runnable runnable) {
        super(j);
        this.c = runnable;
    }

    @Override // java.lang.Runnable
    public final void run() {
        this.c.run();
    }

    @Override // kotlinx.coroutines.W
    public final String toString() {
        return super.toString() + this.c;
    }
}

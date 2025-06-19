package androidx.compose.runtime.snapshots;

/* loaded from: classes.dex */
public abstract class A implements z {
    public final androidx.compose.runtime.internal.a a = new androidx.compose.runtime.internal.a(0);

    public final boolean f(int i) {
        return (i & this.a.get()) != 0;
    }

    public final void h(int i) {
        androidx.compose.runtime.internal.a aVar;
        int i2;
        do {
            aVar = this.a;
            i2 = aVar.get();
            if ((i2 & i) != 0) {
                return;
            }
        } while (!aVar.compareAndSet(i2, i2 | i));
    }
}

package coil3.disk;

/* loaded from: classes.dex */
public final class h implements AutoCloseable {
    public final b a;

    public h(b bVar) {
        this.a = bVar;
    }

    @Override // java.lang.AutoCloseable
    public final void close() {
        this.a.close();
    }
}

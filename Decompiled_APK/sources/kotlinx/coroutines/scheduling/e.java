package kotlinx.coroutines.scheduling;

import kotlinx.coroutines.AbstractC5040y;

/* loaded from: classes3.dex */
public final class e extends h {
    public static final e c;

    static {
        int i = k.c;
        int i2 = k.d;
        long j = k.e;
        String str = k.a;
        e eVar = new e();
        eVar.b = new c(j, i, i2, str);
        c = eVar;
    }

    @Override // kotlinx.coroutines.AbstractC5040y
    public final AbstractC5040y c0(int i) {
        kotlinx.coroutines.internal.b.a(i);
        return i >= k.c ? this : super.c0(i);
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public final void close() {
        throw new UnsupportedOperationException("Dispatchers.Default cannot be closed");
    }

    @Override // kotlinx.coroutines.AbstractC5040y
    public final String toString() {
        return "Dispatchers.Default";
    }
}

package kotlin.random;

import java.io.Serializable;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* loaded from: classes3.dex */
public final class d extends e implements Serializable {
    public d(DefaultConstructorMarker defaultConstructorMarker) {
    }

    private final Object writeReplace() {
        return c.a;
    }

    @Override // kotlin.random.e
    public final int a(int i) {
        return e.b.a(i);
    }

    @Override // kotlin.random.e
    public final double b() {
        return e.b.b();
    }

    @Override // kotlin.random.e
    public final int c() {
        return e.b.c();
    }

    @Override // kotlin.random.e
    public final int d(int i) {
        return e.b.d(i);
    }

    @Override // kotlin.random.e
    public final int e(int i, int i2) {
        return e.b.e(i, i2);
    }

    @Override // kotlin.random.e
    public final long f() {
        return e.b.f();
    }

    @Override // kotlin.random.e
    public final long g(long j, long j2) {
        return e.b.g(0L, 1000L);
    }

    @Override // kotlin.random.e
    public final long h() {
        throw null;
    }
}

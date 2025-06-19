package kotlin.random;

import java.util.Random;

/* loaded from: classes3.dex */
public abstract class a extends e {
    @Override // kotlin.random.e
    public final int a(int i) {
        return ((-i) >> 31) & (j().nextInt() >>> (32 - i));
    }

    @Override // kotlin.random.e
    public final double b() {
        return j().nextDouble();
    }

    @Override // kotlin.random.e
    public final int c() {
        return j().nextInt();
    }

    @Override // kotlin.random.e
    public final int d(int i) {
        return j().nextInt(i);
    }

    @Override // kotlin.random.e
    public final long f() {
        return j().nextLong();
    }

    public abstract Random j();
}

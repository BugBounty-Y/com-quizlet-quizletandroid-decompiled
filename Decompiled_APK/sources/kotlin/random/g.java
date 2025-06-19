package kotlin.random;

import java.io.Serializable;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes3.dex */
public final class g extends e implements Serializable {

    @NotNull
    private static final f i = new f(null);
    public int c;
    public int d;
    public int e;
    public int f;
    public int g;
    public int h;

    public g(int i2, int i3) {
        int i4 = ~i2;
        this.c = i2;
        this.d = i3;
        this.e = 0;
        this.f = 0;
        this.g = i4;
        this.h = (i2 << 10) ^ (i3 >>> 4);
        if ((i2 | i3 | i4) == 0) {
            throw new IllegalArgumentException("Initial state must have at least one non-zero element.");
        }
        for (int i5 = 0; i5 < 64; i5++) {
            c();
        }
    }

    @Override // kotlin.random.e
    public final int a(int i2) {
        return ((-i2) >> 31) & (c() >>> (32 - i2));
    }

    @Override // kotlin.random.e
    public final int c() {
        int i2 = this.c;
        int i3 = i2 ^ (i2 >>> 2);
        this.c = this.d;
        this.d = this.e;
        this.e = this.f;
        int i4 = this.g;
        this.f = i4;
        int i5 = ((i3 ^ (i3 << 1)) ^ i4) ^ (i4 << 4);
        this.g = i5;
        int i6 = this.h + 362437;
        this.h = i6;
        return i5 + i6;
    }
}

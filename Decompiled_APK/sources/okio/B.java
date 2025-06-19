package okio;

import kotlin.collections.C4930v;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class B {
    public final byte[] a;
    public int b;
    public int c;
    public boolean d;
    public final boolean e;
    public B f;
    public B g;

    public B() {
        this.a = new byte[8192];
        this.e = true;
        this.d = false;
    }

    public final B a() {
        B b = this.f;
        if (b == this) {
            b = null;
        }
        B b2 = this.g;
        Intrinsics.d(b2);
        b2.f = this.f;
        B b3 = this.f;
        Intrinsics.d(b3);
        b3.g = this.g;
        this.f = null;
        this.g = null;
        return b;
    }

    public final void b(B segment) {
        Intrinsics.checkNotNullParameter(segment, "segment");
        segment.g = this;
        segment.f = this.f;
        B b = this.f;
        Intrinsics.d(b);
        b.g = segment;
        this.f = segment;
    }

    public final B c() {
        this.d = true;
        return new B(this.a, this.b, this.c, true, false);
    }

    public final void d(B sink, int i) {
        Intrinsics.checkNotNullParameter(sink, "sink");
        if (!sink.e) {
            throw new IllegalStateException("only owner can write");
        }
        int i2 = sink.c;
        int i3 = i2 + i;
        byte[] bArr = sink.a;
        if (i3 > 8192) {
            if (sink.d) {
                throw new IllegalArgumentException();
            }
            int i4 = sink.b;
            if (i3 - i4 > 8192) {
                throw new IllegalArgumentException();
            }
            C4930v.d(0, i4, i2, bArr, bArr);
            sink.c -= sink.b;
            sink.b = 0;
        }
        int i5 = sink.c;
        int i6 = this.b;
        C4930v.d(i5, i6, i6 + i, this.a, bArr);
        sink.c += i;
        this.b += i;
    }

    public B(byte[] data, int i, int i2, boolean z, boolean z2) {
        Intrinsics.checkNotNullParameter(data, "data");
        this.a = data;
        this.b = i;
        this.c = i2;
        this.d = z;
        this.e = z2;
    }
}

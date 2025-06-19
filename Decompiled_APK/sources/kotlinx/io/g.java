package kotlinx.io;

import kotlin.Unit;
import kotlin.collections.C4930v;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class g {
    public final byte[] a;
    public int b;
    public int c;
    public j d;
    public boolean e;
    public g f;
    public g g;

    public g() {
        this.a = new byte[8192];
        this.e = true;
        this.d = null;
    }

    public final int a() {
        return this.a.length - this.c;
    }

    public final int b() {
        return this.c - this.b;
    }

    public final g c() {
        g gVar = this.f;
        g gVar2 = this.g;
        if (gVar2 != null) {
            Intrinsics.d(gVar2);
            gVar2.f = this.f;
        }
        g gVar3 = this.f;
        if (gVar3 != null) {
            Intrinsics.d(gVar3);
            gVar3.g = this.g;
        }
        this.f = null;
        this.g = null;
        return gVar;
    }

    public final void d(g segment) {
        Intrinsics.checkNotNullParameter(segment, "segment");
        segment.g = this;
        segment.f = this.f;
        g gVar = this.f;
        if (gVar != null) {
            gVar.g = segment;
        }
        this.f = segment;
    }

    public final g e() {
        j fVar = this.d;
        if (fVar == null) {
            g gVar = h.a;
            fVar = new f();
            this.d = fVar;
        }
        int i = this.b;
        int i2 = this.c;
        f.b.incrementAndGet((f) fVar);
        Unit unit = Unit.a;
        return new g(this.a, i, i2, fVar);
    }

    public final void f(g sink, int i) {
        Intrinsics.checkNotNullParameter(sink, "sink");
        if (!sink.e) {
            throw new IllegalStateException("only owner can write");
        }
        int i2 = sink.c + i;
        byte[] bArr = sink.a;
        if (i2 > 8192) {
            j jVar = sink.d;
            if (jVar != null ? jVar.b() : false) {
                throw new IllegalArgumentException();
            }
            int i3 = sink.c;
            int i4 = sink.b;
            if ((i3 + i) - i4 > 8192) {
                throw new IllegalArgumentException();
            }
            C4930v.d(0, i4, i3, bArr, bArr);
            sink.c -= sink.b;
            sink.b = 0;
        }
        int i5 = sink.c;
        int i6 = this.b;
        C4930v.d(i5, i6, i6 + i, this.a, bArr);
        sink.c += i;
        this.b += i;
    }

    public g(byte[] bArr, int i, int i2, j jVar) {
        this.a = bArr;
        this.b = i;
        this.c = i2;
        this.d = jVar;
        this.e = false;
    }
}

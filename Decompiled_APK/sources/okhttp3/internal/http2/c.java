package okhttp3.internal.http2;

import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import java.io.EOFException;
import java.util.Arrays;
import kotlin.collections.C4930v;
import kotlin.jvm.internal.Intrinsics;
import okio.C5091h;

/* loaded from: classes3.dex */
public final class c {
    public final C5091h a;
    public int b;
    public boolean c;
    public int d;
    public b[] e;
    public int f;
    public int g;
    public int h;

    public c(C5091h out) {
        Intrinsics.checkNotNullParameter(out, "out");
        this.a = out;
        this.b = SubsamplingScaleImageView.TILE_SIZE_AUTO;
        this.d = 4096;
        this.e = new b[8];
        this.f = 7;
    }

    public final void a(int i) {
        int i2;
        if (i > 0) {
            int length = this.e.length - 1;
            int i3 = 0;
            while (true) {
                i2 = this.f;
                if (length < i2 || i <= 0) {
                    break;
                }
                b bVar = this.e[length];
                Intrinsics.d(bVar);
                i -= bVar.c;
                int i4 = this.h;
                b bVar2 = this.e[length];
                Intrinsics.d(bVar2);
                this.h = i4 - bVar2.c;
                this.g--;
                i3++;
                length--;
            }
            b[] bVarArr = this.e;
            int i5 = i2 + 1;
            System.arraycopy(bVarArr, i5, bVarArr, i5 + i3, this.g);
            b[] bVarArr2 = this.e;
            int i6 = this.f + 1;
            Arrays.fill(bVarArr2, i6, i6 + i3, (Object) null);
            this.f += i3;
        }
    }

    public final void b(b bVar) {
        int i = this.d;
        int i2 = bVar.c;
        if (i2 > i) {
            b[] bVarArr = this.e;
            C4930v.o(bVarArr, null, 0, bVarArr.length);
            this.f = this.e.length - 1;
            this.g = 0;
            this.h = 0;
            return;
        }
        a((this.h + i2) - i);
        int i3 = this.g + 1;
        b[] bVarArr2 = this.e;
        if (i3 > bVarArr2.length) {
            b[] bVarArr3 = new b[bVarArr2.length * 2];
            System.arraycopy(bVarArr2, 0, bVarArr3, bVarArr2.length, bVarArr2.length);
            this.f = this.e.length - 1;
            this.e = bVarArr3;
        }
        int i4 = this.f;
        this.f = i4 - 1;
        this.e[i4] = bVar;
        this.g++;
        this.h += i2;
    }

    public final void c(okio.k source) throws EOFException {
        Intrinsics.checkNotNullParameter(source, "data");
        C5091h c5091h = this.a;
        int[] iArr = x.a;
        Intrinsics.checkNotNullParameter(source, "bytes");
        int iD = source.d();
        long j = 0;
        for (int i = 0; i < iD; i++) {
            byte bJ = source.j(i);
            byte[] bArr = okhttp3.internal.b.a;
            j += x.b[bJ & 255];
        }
        if (((int) ((j + 7) >> 3)) >= source.d()) {
            e(source.d(), 127, 0);
            c5091h.m0(source);
            return;
        }
        C5091h sink = new C5091h();
        int[] iArr2 = x.a;
        Intrinsics.checkNotNullParameter(source, "source");
        Intrinsics.checkNotNullParameter(sink, "sink");
        int iD2 = source.d();
        long j2 = 0;
        int i2 = 0;
        for (int i3 = 0; i3 < iD2; i3++) {
            byte bJ2 = source.j(i3);
            byte[] bArr2 = okhttp3.internal.b.a;
            int i4 = bJ2 & 255;
            int i5 = x.a[i4];
            byte b = x.b[i4];
            j2 = (j2 << b) | i5;
            i2 += b;
            while (i2 >= 8) {
                i2 -= 8;
                sink.p0((int) (j2 >> i2));
            }
        }
        if (i2 > 0) {
            sink.p0((int) ((255 >>> i2) | (j2 << (8 - i2))));
        }
        okio.k kVarD = sink.D(sink.b);
        e(kVarD.d(), 127, 128);
        c5091h.m0(kVarD);
    }

    /* JADX WARN: Removed duplicated region for block: B:22:0x006e  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void d(java.util.ArrayList r14) throws java.io.EOFException {
        /*
            Method dump skipped, instructions count: 259
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: okhttp3.internal.http2.c.d(java.util.ArrayList):void");
    }

    public final void e(int i, int i2, int i3) {
        C5091h c5091h = this.a;
        if (i < i2) {
            c5091h.p0(i | i3);
            return;
        }
        c5091h.p0(i3 | i2);
        int i4 = i - i2;
        while (i4 >= 128) {
            c5091h.p0(128 | (i4 & 127));
            i4 >>>= 7;
        }
        c5091h.p0(i4);
    }
}

package io.ktor.client.plugins;

import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3225o7;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import kotlin.jvm.internal.Intrinsics;
import okio.AbstractC5085b;
import okio.C5091h;

/* renamed from: io.ktor.client.plugins.k, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4864k extends InputStream implements AutoCloseable {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ C4864k(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    private final void a() {
    }

    @Override // java.io.InputStream
    public int available() throws IOException {
        switch (this.a) {
            case 0:
                return ((C4864k) this.b).available();
            case 1:
            default:
                return super.available();
            case 2:
                return (int) Math.min(((C5091h) this.b).b, SubsamplingScaleImageView.TILE_SIZE_AUTO);
            case 3:
                okio.A a = (okio.A) this.b;
                if (a.c) {
                    throw new IOException("closed");
                }
                return (int) Math.min(a.b.b, SubsamplingScaleImageView.TILE_SIZE_AUTO);
        }
    }

    @Override // java.io.InputStream, java.io.Closeable, java.lang.AutoCloseable
    public final void close() throws IOException {
        switch (this.a) {
            case 0:
                super.close();
                ((C4864k) this.b).close();
                break;
            case 1:
                AbstractC3225o7.d((io.ktor.utils.io.n) this.b);
                break;
            case 2:
                break;
            default:
                ((okio.A) this.b).close();
                break;
        }
    }

    @Override // java.io.InputStream
    public final int read() throws Throwable {
        switch (this.a) {
            case 0:
                return ((C4864k) this.b).read();
            case 1:
                io.ktor.utils.io.n nVar = (io.ktor.utils.io.n) this.b;
                if (!nVar.f()) {
                    if (nVar.d().u()) {
                        kotlinx.coroutines.E.D(kotlin.coroutines.n.a, new io.ktor.utils.io.jvm.javaio.a(nVar, null));
                    }
                    if (!nVar.f()) {
                        return nVar.d().readByte() & 255;
                    }
                }
                return -1;
            case 2:
                C5091h c5091h = (C5091h) this.b;
                if (c5091h.b > 0) {
                    return c5091h.readByte() & 255;
                }
                return -1;
            default:
                okio.A a = (okio.A) this.b;
                if (a.c) {
                    throw new IOException("closed");
                }
                C5091h c5091h2 = a.b;
                if (c5091h2.b == 0 && a.a.b0(c5091h2, 8192L) == -1) {
                    return -1;
                }
                return c5091h2.readByte() & 255;
        }
    }

    public String toString() {
        switch (this.a) {
            case 2:
                return ((C5091h) this.b) + ".inputStream()";
            case 3:
                return ((okio.A) this.b) + ".inputStream()";
            default:
                return super.toString();
        }
    }

    @Override // java.io.InputStream
    public long transferTo(OutputStream out) throws IOException {
        switch (this.a) {
            case 3:
                Intrinsics.checkNotNullParameter(out, "out");
                okio.A a = (okio.A) this.b;
                if (a.c) {
                    throw new IOException("closed");
                }
                long j = 0;
                long j2 = 0;
                while (true) {
                    C5091h c5091h = a.b;
                    if (c5091h.b == j && a.a.b0(c5091h, 8192L) == -1) {
                        return j2;
                    }
                    long j3 = c5091h.b;
                    j2 += j3;
                    Intrinsics.checkNotNullParameter(out, "out");
                    AbstractC5085b.e(c5091h.b, 0L, j3);
                    okio.B b = c5091h.a;
                    while (j3 > j) {
                        Intrinsics.d(b);
                        int iMin = (int) Math.min(j3, b.c - b.b);
                        out.write(b.a, b.b, iMin);
                        int i = b.b + iMin;
                        b.b = i;
                        long j4 = iMin;
                        c5091h.b -= j4;
                        j3 -= j4;
                        if (i == b.c) {
                            okio.B bA = b.a();
                            c5091h.a = bA;
                            okio.C.a(b);
                            b = bA;
                        }
                        j = 0;
                    }
                }
                break;
            default:
                return super.transferTo(out);
        }
    }

    @Override // java.io.InputStream
    public final int read(byte[] b, int i, int i2) throws Throwable {
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(b, "b");
                return ((C4864k) this.b).read(b, i, i2);
            case 1:
                Intrinsics.checkNotNullParameter(b, "b");
                io.ktor.utils.io.n nVar = (io.ktor.utils.io.n) this.b;
                if (!nVar.f()) {
                    if (nVar.d().u()) {
                        kotlinx.coroutines.E.D(kotlin.coroutines.n.a, new io.ktor.utils.io.jvm.javaio.a(nVar, null));
                    }
                    Intrinsics.checkNotNullParameter(nVar, "<this>");
                    int iG0 = nVar.d().g0(i, b, Math.min((int) nVar.d().c().c, i2) + i);
                    if (iG0 >= 0) {
                        return iG0;
                    }
                    if (!nVar.f()) {
                        return 0;
                    }
                }
                return -1;
            case 2:
                Intrinsics.checkNotNullParameter(b, "sink");
                return ((C5091h) this.b).read(b, i, i2);
            default:
                Intrinsics.checkNotNullParameter(b, "data");
                okio.A a = (okio.A) this.b;
                if (!a.c) {
                    AbstractC5085b.e(b.length, i, i2);
                    C5091h c5091h = a.b;
                    if (c5091h.b == 0 && a.a.b0(c5091h, 8192L) == -1) {
                        return -1;
                    }
                    return c5091h.read(b, i, i2);
                }
                throw new IOException("closed");
        }
    }
}

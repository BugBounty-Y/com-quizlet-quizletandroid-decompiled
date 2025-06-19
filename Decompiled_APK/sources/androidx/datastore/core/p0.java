package androidx.datastore.core;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class p0 extends OutputStream implements AutoCloseable {
    public final /* synthetic */ int a = 0;
    public final Object b;

    public p0(FileOutputStream fileOutputStream) {
        Intrinsics.checkNotNullParameter(fileOutputStream, "fileOutputStream");
        this.b = fileOutputStream;
    }

    private final void a() {
    }

    @Override // java.io.OutputStream, java.io.Closeable, java.lang.AutoCloseable
    public final void close() {
        switch (this.a) {
            case 0:
                break;
            default:
                ((okio.z) this.b).close();
                break;
        }
    }

    @Override // java.io.OutputStream, java.io.Flushable
    public final void flush() throws IOException {
        switch (this.a) {
            case 0:
                ((FileOutputStream) this.b).flush();
                break;
            default:
                okio.z zVar = (okio.z) this.b;
                if (!zVar.c) {
                    zVar.flush();
                    break;
                }
                break;
        }
    }

    public String toString() {
        switch (this.a) {
            case 1:
                return ((okio.z) this.b) + ".outputStream()";
            default:
                return super.toString();
        }
    }

    @Override // java.io.OutputStream
    public void write(byte[] b) throws IOException {
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(b, "b");
                ((FileOutputStream) this.b).write(b);
                break;
            default:
                super.write(b);
                break;
        }
    }

    public p0(okio.z zVar) {
        this.b = zVar;
    }

    @Override // java.io.OutputStream
    public final void write(int i) throws IOException {
        switch (this.a) {
            case 0:
                ((FileOutputStream) this.b).write(i);
                return;
            default:
                okio.z zVar = (okio.z) this.b;
                if (zVar.c) {
                    throw new IOException("closed");
                }
                zVar.b.p0((byte) i);
                zVar.a();
                return;
        }
    }

    @Override // java.io.OutputStream
    public final void write(byte[] bytes, int i, int i2) throws IOException {
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(bytes, "bytes");
                ((FileOutputStream) this.b).write(bytes, i, i2);
                return;
            default:
                Intrinsics.checkNotNullParameter(bytes, "data");
                okio.z zVar = (okio.z) this.b;
                if (!zVar.c) {
                    zVar.b.o0(bytes, i, i2);
                    zVar.a();
                    return;
                }
                throw new IOException("closed");
        }
    }
}

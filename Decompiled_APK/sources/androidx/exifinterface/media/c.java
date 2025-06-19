package androidx.exifinterface.media;

import java.io.DataOutputStream;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteOrder;

/* loaded from: classes.dex */
public final class c extends FilterOutputStream {
    public final DataOutputStream a;
    public ByteOrder b;

    public c(OutputStream outputStream, ByteOrder byteOrder) {
        super(outputStream);
        this.a = new DataOutputStream(outputStream);
        this.b = byteOrder;
    }

    public final void a(int i) throws IOException {
        this.a.write(i);
    }

    public final void d(int i) throws IOException {
        ByteOrder byteOrder = this.b;
        ByteOrder byteOrder2 = ByteOrder.LITTLE_ENDIAN;
        DataOutputStream dataOutputStream = this.a;
        if (byteOrder == byteOrder2) {
            dataOutputStream.write(i & 255);
            dataOutputStream.write((i >>> 8) & 255);
            dataOutputStream.write((i >>> 16) & 255);
            dataOutputStream.write((i >>> 24) & 255);
            return;
        }
        if (byteOrder == ByteOrder.BIG_ENDIAN) {
            dataOutputStream.write((i >>> 24) & 255);
            dataOutputStream.write((i >>> 16) & 255);
            dataOutputStream.write((i >>> 8) & 255);
            dataOutputStream.write(i & 255);
        }
    }

    public final void f(short s) throws IOException {
        ByteOrder byteOrder = this.b;
        ByteOrder byteOrder2 = ByteOrder.LITTLE_ENDIAN;
        DataOutputStream dataOutputStream = this.a;
        if (byteOrder == byteOrder2) {
            dataOutputStream.write(s & 255);
            dataOutputStream.write((s >>> 8) & 255);
        } else if (byteOrder == ByteOrder.BIG_ENDIAN) {
            dataOutputStream.write((s >>> 8) & 255);
            dataOutputStream.write(s & 255);
        }
    }

    public final void i(long j) throws IOException {
        if (j > 4294967295L) {
            throw new IllegalArgumentException("val is larger than the maximum value of a 32-bit unsigned integer");
        }
        d((int) j);
    }

    public final void j(int i) throws IOException {
        if (i > 65535) {
            throw new IllegalArgumentException("val is larger than the maximum value of a 16-bit unsigned integer");
        }
        f((short) i);
    }

    @Override // java.io.FilterOutputStream, java.io.OutputStream
    public final void write(byte[] bArr) throws IOException {
        this.a.write(bArr);
    }

    @Override // java.io.FilterOutputStream, java.io.OutputStream
    public final void write(byte[] bArr, int i, int i2) throws IOException {
        this.a.write(bArr, i, i2);
    }
}

package coil3.fetch;

import java.nio.ByteBuffer;
import okio.C5091h;
import okio.G;
import okio.I;

/* loaded from: classes.dex */
public final class d implements G {
    public final ByteBuffer a;
    public final int b;

    public d(ByteBuffer byteBuffer) {
        ByteBuffer byteBufferSlice = byteBuffer.slice();
        this.a = byteBufferSlice;
        this.b = byteBufferSlice.capacity();
    }

    @Override // okio.G
    public final long b0(C5091h c5091h, long j) {
        ByteBuffer byteBuffer = this.a;
        int iPosition = byteBuffer.position();
        int i = this.b;
        if (iPosition == i) {
            return -1L;
        }
        int iPosition2 = (int) (byteBuffer.position() + j);
        if (iPosition2 <= i) {
            i = iPosition2;
        }
        byteBuffer.limit(i);
        return c5091h.write(byteBuffer);
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public final void close() {
    }

    @Override // okio.G
    public final I h() {
        return I.d;
    }
}

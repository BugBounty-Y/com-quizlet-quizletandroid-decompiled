package okio;

import java.nio.channels.WritableByteChannel;

/* renamed from: okio.i, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public interface InterfaceC5092i extends E, WritableByteChannel {
    InterfaceC5092i F(int i, byte[] bArr);

    InterfaceC5092i H(String str);

    long M(G g);

    InterfaceC5092i O(int i, int i2, String str);

    InterfaceC5092i X(byte[] bArr);

    InterfaceC5092i Z(k kVar);

    C5091h c();

    @Override // okio.E, java.io.Flushable
    void flush();

    InterfaceC5092i h0(long j);

    InterfaceC5092i v(int i);
}

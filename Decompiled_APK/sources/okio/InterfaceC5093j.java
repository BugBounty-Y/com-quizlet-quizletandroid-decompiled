package okio;

import java.io.InputStream;
import java.nio.channels.ReadableByteChannel;
import java.nio.charset.Charset;

/* renamed from: okio.j, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public interface InterfaceC5093j extends G, ReadableByteChannel {
    boolean J(long j, k kVar);

    String K(Charset charset);

    String S();

    String U();

    C5091h c();

    boolean e(long j);

    long e0(InterfaceC5092i interfaceC5092i);

    InputStream i0();

    int j0(w wVar);

    void k(long j);

    A peek();

    void skip(long j);

    long t(k kVar);

    void w(C5091h c5091h, long j);

    long x(k kVar);
}

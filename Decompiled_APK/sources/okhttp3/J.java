package okhttp3;

import java.io.Closeable;
import java.io.IOException;
import java.nio.charset.Charset;
import kotlin.text.Charsets;
import okio.InterfaceC5093j;

/* loaded from: classes3.dex */
public abstract class J implements Closeable, AutoCloseable {
    public abstract long a();

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public void close() {
        okhttp3.internal.b.d(f0());
    }

    public abstract w d();

    public final String f() throws IOException {
        Charset charsetA;
        InterfaceC5093j interfaceC5093jF0 = f0();
        try {
            w wVarD = d();
            if (wVarD == null || (charsetA = wVarD.a(Charsets.UTF_8)) == null) {
                charsetA = Charsets.UTF_8;
            }
            String strK = interfaceC5093jF0.K(okhttp3.internal.b.t(interfaceC5093jF0, charsetA));
            interfaceC5093jF0.close();
            return strK;
        } finally {
        }
    }

    public abstract InterfaceC5093j f0();
}

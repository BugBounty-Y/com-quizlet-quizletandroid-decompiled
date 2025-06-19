package okhttp3.internal.platform.android;

import androidx.compose.ui.node.B;
import javax.net.ssl.SSLSocket;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.D;

/* loaded from: classes3.dex */
public final class e implements k {
    @Override // okhttp3.internal.platform.android.k
    public final boolean a(SSLSocket sslSocket) {
        Intrinsics.checkNotNullParameter(sslSocket, "sslSocket");
        String name = sslSocket.getClass().getName();
        Intrinsics.checkNotNullExpressionValue(name, "sslSocket.javaClass.name");
        return D.r(name, "com.google.android.gms.org.conscrypt.", false);
    }

    @Override // okhttp3.internal.platform.android.k
    public final m b(SSLSocket sslSocket) {
        Intrinsics.checkNotNullParameter(sslSocket, "sslSocket");
        e eVar = f.f;
        Class<?> cls = sslSocket.getClass();
        Class<?> superclass = cls;
        while (!superclass.getSimpleName().equals("OpenSSLSocketImpl")) {
            superclass = superclass.getSuperclass();
            if (superclass == null) {
                throw new AssertionError(B.d(cls, "No OpenSSLSocketImpl superclass of socket of type "));
            }
        }
        return new f(superclass);
    }
}

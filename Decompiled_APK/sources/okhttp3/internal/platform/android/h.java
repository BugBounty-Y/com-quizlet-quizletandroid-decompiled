package okhttp3.internal.platform.android;

import java.util.List;
import javax.net.ssl.SSLSocket;
import kotlin.jvm.internal.Intrinsics;
import okhttp3.internal.platform.o;
import org.bouncycastle.jsse.BCSSLParameters;
import org.bouncycastle.jsse.BCSSLSocket;

/* loaded from: classes3.dex */
public final class h implements m {
    public static final g a = new g();

    @Override // okhttp3.internal.platform.android.m
    public final boolean a(SSLSocket sslSocket) {
        Intrinsics.checkNotNullParameter(sslSocket, "sslSocket");
        return false;
    }

    @Override // okhttp3.internal.platform.android.m
    public final boolean b() {
        boolean z = okhttp3.internal.platform.e.d;
        return okhttp3.internal.platform.e.d;
    }

    @Override // okhttp3.internal.platform.android.m
    public final String c(SSLSocket sslSocket) {
        Intrinsics.checkNotNullParameter(sslSocket, "sslSocket");
        String applicationProtocol = ((BCSSLSocket) sslSocket).getApplicationProtocol();
        if (applicationProtocol == null ? true : applicationProtocol.equals("")) {
            return null;
        }
        return applicationProtocol;
    }

    @Override // okhttp3.internal.platform.android.m
    public final void d(SSLSocket sslSocket, String str, List protocols) {
        Intrinsics.checkNotNullParameter(sslSocket, "sslSocket");
        Intrinsics.checkNotNullParameter(protocols, "protocols");
        if (a(sslSocket)) {
            BCSSLSocket bCSSLSocket = (BCSSLSocket) sslSocket;
            BCSSLParameters parameters = bCSSLSocket.getParameters();
            o oVar = o.a;
            parameters.setApplicationProtocols((String[]) com.quizlet.quizletandroid.ui.common.adapter.c.d(protocols).toArray(new String[0]));
            bCSSLSocket.setParameters(parameters);
        }
    }
}

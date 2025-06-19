package okhttp3.internal.platform.android;

import java.util.List;
import javax.net.ssl.SSLSocket;
import kotlin.jvm.internal.Intrinsics;
import okhttp3.internal.platform.o;
import org.conscrypt.Conscrypt;

/* loaded from: classes3.dex */
public final class j implements m {
    public static final i a = new i();

    @Override // okhttp3.internal.platform.android.m
    public final boolean a(SSLSocket sslSocket) {
        Intrinsics.checkNotNullParameter(sslSocket, "sslSocket");
        return Conscrypt.isConscrypt(sslSocket);
    }

    @Override // okhttp3.internal.platform.android.m
    public final boolean b() {
        boolean z = okhttp3.internal.platform.h.d;
        return okhttp3.internal.platform.h.d;
    }

    @Override // okhttp3.internal.platform.android.m
    public final String c(SSLSocket sslSocket) {
        Intrinsics.checkNotNullParameter(sslSocket, "sslSocket");
        if (a(sslSocket)) {
            return Conscrypt.getApplicationProtocol(sslSocket);
        }
        return null;
    }

    @Override // okhttp3.internal.platform.android.m
    public final void d(SSLSocket sslSocket, String str, List protocols) {
        Intrinsics.checkNotNullParameter(sslSocket, "sslSocket");
        Intrinsics.checkNotNullParameter(protocols, "protocols");
        if (a(sslSocket)) {
            Conscrypt.setUseSessionTickets(sslSocket, true);
            o oVar = o.a;
            Conscrypt.setApplicationProtocols(sslSocket, (String[]) com.quizlet.quizletandroid.ui.common.adapter.c.d(protocols).toArray(new String[0]));
        }
    }
}

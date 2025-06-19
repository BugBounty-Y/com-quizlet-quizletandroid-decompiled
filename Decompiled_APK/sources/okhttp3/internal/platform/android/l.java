package okhttp3.internal.platform.android;

import java.util.List;
import javax.net.ssl.SSLSocket;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class l implements m {
    public final k a;
    public m b;

    public l(k socketAdapterFactory) {
        Intrinsics.checkNotNullParameter(socketAdapterFactory, "socketAdapterFactory");
        this.a = socketAdapterFactory;
    }

    @Override // okhttp3.internal.platform.android.m
    public final boolean a(SSLSocket sslSocket) {
        Intrinsics.checkNotNullParameter(sslSocket, "sslSocket");
        return this.a.a(sslSocket);
    }

    @Override // okhttp3.internal.platform.android.m
    public final boolean b() {
        return true;
    }

    @Override // okhttp3.internal.platform.android.m
    public final String c(SSLSocket sslSocket) {
        Intrinsics.checkNotNullParameter(sslSocket, "sslSocket");
        m mVarE = e(sslSocket);
        if (mVarE != null) {
            return mVarE.c(sslSocket);
        }
        return null;
    }

    @Override // okhttp3.internal.platform.android.m
    public final void d(SSLSocket sslSocket, String str, List protocols) {
        Intrinsics.checkNotNullParameter(sslSocket, "sslSocket");
        Intrinsics.checkNotNullParameter(protocols, "protocols");
        m mVarE = e(sslSocket);
        if (mVarE != null) {
            mVarE.d(sslSocket, str, protocols);
        }
    }

    public final synchronized m e(SSLSocket sSLSocket) {
        try {
            if (this.b == null && this.a.a(sSLSocket)) {
                this.b = this.a.b(sSLSocket);
            }
        } catch (Throwable th) {
            throw th;
        }
        return this.b;
    }
}

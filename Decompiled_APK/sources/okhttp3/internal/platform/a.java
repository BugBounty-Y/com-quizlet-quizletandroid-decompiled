package okhttp3.internal.platform;

import android.net.http.X509TrustManagerExtensions;
import android.os.Build;
import android.security.NetworkSecurityPolicy;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.X509TrustManager;
import kotlin.collections.C4933y;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a extends o {
    public static final boolean d;
    public final ArrayList c;

    static {
        d = com.quizlet.quizletandroid.ui.common.adapter.c.g() && Build.VERSION.SDK_INT >= 29;
    }

    public a() {
        okhttp3.internal.platform.android.m[] elements = {(!com.quizlet.quizletandroid.ui.common.adapter.c.g() || Build.VERSION.SDK_INT < 29) ? null : new okhttp3.internal.platform.android.a(), new okhttp3.internal.platform.android.l(okhttp3.internal.platform.android.f.f), new okhttp3.internal.platform.android.l(okhttp3.internal.platform.android.j.a), new okhttp3.internal.platform.android.l(okhttp3.internal.platform.android.h.a)};
        Intrinsics.checkNotNullParameter(elements, "elements");
        ArrayList arrayListZ = C4933y.z(elements);
        ArrayList arrayList = new ArrayList();
        Iterator it2 = arrayListZ.iterator();
        while (it2.hasNext()) {
            Object next = it2.next();
            if (((okhttp3.internal.platform.android.m) next).b()) {
                arrayList.add(next);
            }
        }
        this.c = arrayList;
    }

    @Override // okhttp3.internal.platform.o
    public final AbstractC3375o2 b(X509TrustManager trustManager) {
        X509TrustManagerExtensions x509TrustManagerExtensions;
        Intrinsics.checkNotNullParameter(trustManager, "trustManager");
        Intrinsics.checkNotNullParameter(trustManager, "trustManager");
        try {
            x509TrustManagerExtensions = new X509TrustManagerExtensions(trustManager);
        } catch (IllegalArgumentException unused) {
            x509TrustManagerExtensions = null;
        }
        okhttp3.internal.platform.android.b bVar = x509TrustManagerExtensions != null ? new okhttp3.internal.platform.android.b(trustManager, x509TrustManagerExtensions) : null;
        return bVar != null ? bVar : super.b(trustManager);
    }

    @Override // okhttp3.internal.platform.o
    public final void d(SSLSocket sslSocket, String str, List protocols) {
        Object next;
        Intrinsics.checkNotNullParameter(sslSocket, "sslSocket");
        Intrinsics.checkNotNullParameter(protocols, "protocols");
        Iterator it2 = this.c.iterator();
        while (true) {
            if (!it2.hasNext()) {
                next = null;
                break;
            } else {
                next = it2.next();
                if (((okhttp3.internal.platform.android.m) next).a(sslSocket)) {
                    break;
                }
            }
        }
        okhttp3.internal.platform.android.m mVar = (okhttp3.internal.platform.android.m) next;
        if (mVar != null) {
            mVar.d(sslSocket, str, protocols);
        }
    }

    @Override // okhttp3.internal.platform.o
    public final String f(SSLSocket sslSocket) {
        Object next;
        Intrinsics.checkNotNullParameter(sslSocket, "sslSocket");
        Iterator it2 = this.c.iterator();
        while (true) {
            if (!it2.hasNext()) {
                next = null;
                break;
            }
            next = it2.next();
            if (((okhttp3.internal.platform.android.m) next).a(sslSocket)) {
                break;
            }
        }
        okhttp3.internal.platform.android.m mVar = (okhttp3.internal.platform.android.m) next;
        if (mVar != null) {
            return mVar.c(sslSocket);
        }
        return null;
    }

    @Override // okhttp3.internal.platform.o
    public final boolean h(String hostname) {
        Intrinsics.checkNotNullParameter(hostname, "hostname");
        return NetworkSecurityPolicy.getInstance().isCleartextTrafficPermitted(hostname);
    }
}

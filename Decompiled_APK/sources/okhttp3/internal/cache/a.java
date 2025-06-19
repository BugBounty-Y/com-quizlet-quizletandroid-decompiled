package okhttp3.internal.cache;

import okhttp3.G;
import okhttp3.H;

/* loaded from: classes3.dex */
public final class a {
    public static final H a(H h) {
        if ((h != null ? h.g : null) == null) {
            return h;
        }
        G gF = h.f();
        gF.g = null;
        return gF.a();
    }

    public static boolean b(String str) {
        return ("Connection".equalsIgnoreCase(str) || "Keep-Alive".equalsIgnoreCase(str) || "Proxy-Authenticate".equalsIgnoreCase(str) || "Proxy-Authorization".equalsIgnoreCase(str) || "TE".equalsIgnoreCase(str) || "Trailers".equalsIgnoreCase(str) || "Transfer-Encoding".equalsIgnoreCase(str) || "Upgrade".equalsIgnoreCase(str)) ? false : true;
    }
}

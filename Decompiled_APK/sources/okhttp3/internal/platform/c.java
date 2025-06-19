package okhttp3.internal.platform;

import android.net.http.X509TrustManagerExtensions;
import android.os.Build;
import android.security.NetworkSecurityPolicy;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.X509TrustManager;
import kotlin.collections.C4933y;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c extends o {
    public static final boolean e;
    public final ArrayList c;
    public final com.quizlet.data.repository.classfolder.e d;

    static {
        boolean z = false;
        if (com.quizlet.quizletandroid.ui.common.adapter.c.g() && Build.VERSION.SDK_INT < 30) {
            z = true;
        }
        e = z;
    }

    public c() throws NoSuchMethodException, ClassNotFoundException, SecurityException {
        okhttp3.internal.platform.android.n nVar;
        Method method;
        Method method2;
        int i = okhttp3.internal.platform.android.n.g;
        Intrinsics.checkNotNullParameter("com.android.org.conscrypt", "packageName");
        Method method3 = null;
        try {
            Class<?> sslSocketClass = Class.forName("com.android.org.conscrypt.OpenSSLSocketImpl");
            Class<?> sslSocketFactoryClass = Class.forName("com.android.org.conscrypt.OpenSSLSocketFactoryImpl");
            Class<?> paramClass = Class.forName("com.android.org.conscrypt.SSLParametersImpl");
            Intrinsics.checkNotNullExpressionValue(paramClass, "paramsClass");
            Intrinsics.checkNotNullParameter(sslSocketClass, "sslSocketClass");
            Intrinsics.checkNotNullParameter(sslSocketFactoryClass, "sslSocketFactoryClass");
            Intrinsics.checkNotNullParameter(paramClass, "paramClass");
            nVar = new okhttp3.internal.platform.android.n(sslSocketClass);
        } catch (Exception e2) {
            o.a.getClass();
            o.i(5, "unable to load android socket classes", e2);
            nVar = null;
        }
        okhttp3.internal.platform.android.m[] elements = {nVar, new okhttp3.internal.platform.android.l(okhttp3.internal.platform.android.f.f), new okhttp3.internal.platform.android.l(okhttp3.internal.platform.android.j.a), new okhttp3.internal.platform.android.l(okhttp3.internal.platform.android.h.a)};
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
        try {
            Class<?> cls = Class.forName("dalvik.system.CloseGuard");
            Method method4 = cls.getMethod("get", null);
            method2 = cls.getMethod("open", String.class);
            method = cls.getMethod("warnIfOpen", null);
            method3 = method4;
        } catch (Exception unused) {
            method = null;
            method2 = null;
        }
        this.d = new com.quizlet.data.repository.classfolder.e(method3, method2, method, 19);
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
    public final okhttp3.internal.tls.d c(X509TrustManager trustManager) throws NoSuchMethodException, SecurityException {
        Intrinsics.checkNotNullParameter(trustManager, "trustManager");
        try {
            Method method = trustManager.getClass().getDeclaredMethod("findTrustAnchorByIssuerAndSignature", X509Certificate.class);
            method.setAccessible(true);
            Intrinsics.checkNotNullExpressionValue(method, "method");
            return new b(trustManager, method);
        } catch (NoSuchMethodException unused) {
            return super.c(trustManager);
        }
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
    public final void e(Socket socket, InetSocketAddress address, int i) throws IOException {
        Intrinsics.checkNotNullParameter(socket, "socket");
        Intrinsics.checkNotNullParameter(address, "address");
        try {
            socket.connect(address, i);
        } catch (ClassCastException e2) {
            if (Build.VERSION.SDK_INT != 26) {
                throw e2;
            }
            throw new IOException("Exception in connect", e2);
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
    public final Object g() throws IllegalAccessException, IllegalArgumentException, InvocationTargetException {
        Intrinsics.checkNotNullParameter("response.body().close()", "closer");
        com.quizlet.data.repository.classfolder.e eVar = this.d;
        eVar.getClass();
        Intrinsics.checkNotNullParameter("response.body().close()", "closer");
        Method method = (Method) eVar.b;
        if (method != null) {
            try {
                Object objInvoke = method.invoke(null, null);
                Method method2 = (Method) eVar.c;
                Intrinsics.d(method2);
                method2.invoke(objInvoke, "response.body().close()");
                return objInvoke;
            } catch (Exception unused) {
            }
        }
        return null;
    }

    @Override // okhttp3.internal.platform.o
    public final boolean h(String hostname) {
        Intrinsics.checkNotNullParameter(hostname, "hostname");
        return NetworkSecurityPolicy.getInstance().isCleartextTrafficPermitted(hostname);
    }

    @Override // okhttp3.internal.platform.o
    public final void j(Object obj, String message) throws IllegalAccessException, IllegalArgumentException, InvocationTargetException {
        Intrinsics.checkNotNullParameter(message, "message");
        com.quizlet.data.repository.classfolder.e eVar = this.d;
        eVar.getClass();
        if (obj != null) {
            try {
                Method method = (Method) eVar.d;
                Intrinsics.d(method);
                method.invoke(obj, null);
                return;
            } catch (Exception unused) {
            }
        }
        o.i(5, message, null);
    }
}

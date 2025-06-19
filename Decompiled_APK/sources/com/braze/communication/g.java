package com.braze.communication;

import com.braze.Y;
import com.braze.support.BrazeLogger;
import com.google.firebase.perf.network.FirebasePerfUrlConnection;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import javax.net.ssl.HttpsURLConnection;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class g {
    public static final g a = new g();
    public static final f b;

    static {
        try {
            b = new f();
        } catch (Exception e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) a, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new Y(11), 4, (Object) null);
        }
    }

    public static final String a() {
        return "Exception initializing static TLS socket factory.";
    }

    public static final String b() {
        return "Exception setting TLS socket factory on url connection.";
    }

    public final HttpURLConnection a(URL url) {
        Intrinsics.checkNotNullParameter(url, "url");
        URLConnection uRLConnection = (URLConnection) FirebasePerfUrlConnection.instrument(url.openConnection());
        if (Intrinsics.b(url.getProtocol(), "https")) {
            try {
                Intrinsics.e(uRLConnection, "null cannot be cast to non-null type javax.net.ssl.HttpsURLConnection");
                HttpsURLConnection httpsURLConnection = (HttpsURLConnection) uRLConnection;
                f fVar = b;
                if (fVar == null) {
                    Intrinsics.m("socketFactory");
                    throw null;
                }
                httpsURLConnection.setSSLSocketFactory(fVar);
            } catch (Exception e) {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new Y(12), 4, (Object) null);
            }
        }
        Intrinsics.e(uRLConnection, "null cannot be cast to non-null type java.net.HttpURLConnection");
        return (HttpURLConnection) uRLConnection;
    }
}

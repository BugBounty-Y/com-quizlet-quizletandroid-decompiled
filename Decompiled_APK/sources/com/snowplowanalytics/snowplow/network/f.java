package com.snowplowanalytics.snowplow.network;

import android.net.Uri;
import android.os.Build;
import androidx.compose.animation.d0;
import com.amazon.device.ads.DtbConstants;
import com.google.android.gms.internal.ads.C1881be;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3347h2;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import javax.net.ssl.X509TrustManager;
import kotlin.jvm.internal.Intrinsics;
import okhttp3.A;
import okhttp3.internal.platform.o;
import okhttp3.n;
import okhttp3.w;
import okhttp3.z;

/* loaded from: classes3.dex */
public final class f implements d {
    public static final String i = d0.s(new Object[]{"andr-6.2.0", Build.VERSION.RELEASE}, 2, "snowplow/%s android/%s", "format(format, *args)");
    public final String a = f.class.getSimpleName();
    public final w b;
    public final c c;
    public final int d;
    public boolean e;
    public final Map f;
    public final A g;
    public final Uri.Builder h;

    public f(e eVar) {
        int iHashCode;
        Pattern pattern = w.e;
        this.b = AbstractC3347h2.d("application/json; charset=utf-8");
        String str = eVar.a;
        Uri uri = Uri.parse(str);
        if (uri.getScheme() == null) {
            str = DtbConstants.HTTPS + eVar.a;
        } else {
            String scheme = uri.getScheme();
            if (scheme == null || ((iHashCode = scheme.hashCode()) == 3213448 ? !scheme.equals("http") : !(iHashCode == 99617003 && scheme.equals("https")))) {
                str = DtbConstants.HTTPS + eVar.a;
            }
        }
        c cVar = eVar.c;
        this.c = cVar;
        this.d = eVar.e;
        String str2 = eVar.h;
        this.e = eVar.i;
        this.f = eVar.j;
        io.ktor.client.plugins.api.d dVar = new io.ktor.client.plugins.api.d(eVar.d);
        Uri.Builder builderBuildUpon = Uri.parse(str).buildUpon();
        Intrinsics.checkNotNullExpressionValue(builderBuildUpon, "parse(networkUri).buildUpon()");
        this.h = builderBuildUpon;
        if (cVar == c.a) {
            builderBuildUpon.appendPath("i");
        } else if (str2 == null) {
            builderBuildUpon.appendEncodedPath("com.snowplowanalytics.snowplow/tp2");
        } else {
            builderBuildUpon.appendEncodedPath(str2);
        }
        A a = eVar.f;
        if (a == null) {
            z zVar = new z();
            C1881be sslSocketFactory = (C1881be) dVar.d;
            if (sslSocketFactory == null) {
                Intrinsics.m("sslSocketFactory");
                throw null;
            }
            X509TrustManager trustManager = (X509TrustManager) dVar.c;
            if (trustManager == null) {
                Intrinsics.m("trustManager");
                throw null;
            }
            Intrinsics.checkNotNullParameter(sslSocketFactory, "sslSocketFactory");
            Intrinsics.checkNotNullParameter(trustManager, "trustManager");
            if (!sslSocketFactory.equals(zVar.o) || !trustManager.equals(zVar.p)) {
                zVar.z = null;
            }
            zVar.o = sslSocketFactory;
            Intrinsics.checkNotNullParameter(trustManager, "trustManager");
            o oVar = o.a;
            zVar.u = o.a.b(trustManager);
            zVar.p = trustManager;
            TimeUnit unit = TimeUnit.SECONDS;
            Intrinsics.checkNotNullParameter(unit, "unit");
            zVar.v = okhttp3.internal.b.b("timeout", 15L, unit);
            zVar.c(15L, unit);
            n cookieJar = eVar.g;
            cookieJar = cookieJar == null ? new b(eVar.b) : cookieJar;
            Intrinsics.checkNotNullParameter(cookieJar, "cookieJar");
            zVar.j = cookieJar;
            a = new A(zVar);
        }
        this.g = a;
    }
}

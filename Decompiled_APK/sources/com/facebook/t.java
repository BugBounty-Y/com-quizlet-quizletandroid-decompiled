package com.facebook;

import android.net.Uri;
import android.os.Bundle;
import androidx.compose.animation.d0;
import com.facebook.internal.AbstractC1554i;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;
import kotlin.collections.C4933y;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.D;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class t {
    public static final String j;
    public static final Pattern k;
    public static volatile String l;
    public final AccessToken a;
    public final String b;
    public JSONObject c;
    public Bundle d;
    public String e;
    public final String f;
    public q g;
    public x h;
    public boolean i;

    static {
        char[] charArray = "-_1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".toCharArray();
        Intrinsics.checkNotNullExpressionValue(charArray, "this as java.lang.String).toCharArray()");
        StringBuilder sb = new StringBuilder();
        SecureRandom secureRandom = new SecureRandom();
        int iNextInt = secureRandom.nextInt(11) + 30;
        for (int i = 0; i < iNextInt; i++) {
            sb.append(charArray[secureRandom.nextInt(charArray.length)]);
        }
        String string = sb.toString();
        Intrinsics.checkNotNullExpressionValue(string, "buffer.toString()");
        j = string;
        k = Pattern.compile("^/?v\\d+\\.\\d+/(.*)");
    }

    public t(AccessToken accessToken, String str, Bundle bundle, x xVar, q qVar) {
        this.a = accessToken;
        this.b = str;
        this.f = null;
        j(qVar);
        this.h = xVar == null ? x.a : xVar;
        if (bundle != null) {
            this.d = new Bundle(bundle);
        } else {
            this.d = new Bundle();
        }
        this.f = o.d();
    }

    public static String f() {
        String strB = o.b();
        AbstractC1554i.k();
        String str = o.f;
        if (str == null) {
            throw new FacebookException("A valid Facebook client token must be set in the AndroidManifest.xml or set by calling FacebookSdk.setClientToken before initializing the sdk. Visit https://developers.facebook.com/docs/android/getting-started#add-app_id for more information.");
        }
        if (strB.length() <= 0 || str.length() <= 0) {
            return null;
        }
        return strB + '|' + str;
    }

    /* JADX WARN: Removed duplicated region for block: B:20:0x003d  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void a() {
        /*
            r6 = this;
            android.os.Bundle r0 = r6.d
            java.lang.String r1 = r6.e()
            r2 = 0
            if (r1 == 0) goto L10
            java.lang.String r3 = "|"
            boolean r3 = kotlin.text.StringsKt.G(r1, r3, r2)
            goto L11
        L10:
            r3 = r2
        L11:
            java.lang.String r4 = "access_token"
            if (r1 == 0) goto L26
            java.lang.String r5 = "IG"
            boolean r1 = kotlin.text.D.r(r1, r5, r2)
            if (r1 == 0) goto L26
            if (r3 != 0) goto L26
            boolean r1 = r6.i()
            if (r1 == 0) goto L26
            goto L3d
        L26:
            java.lang.String r1 = com.facebook.o.e()
            java.lang.String r2 = "instagram.com"
            boolean r1 = kotlin.jvm.internal.Intrinsics.b(r1, r2)
            r2 = 1
            if (r1 != 0) goto L34
            goto L39
        L34:
            boolean r1 = r6.i()
            r2 = r2 ^ r1
        L39:
            if (r2 != 0) goto L45
            if (r3 != 0) goto L45
        L3d:
            java.lang.String r1 = f()
            r0.putString(r4, r1)
            goto L4e
        L45:
            java.lang.String r1 = r6.e()
            if (r1 == 0) goto L4e
            r0.putString(r4, r1)
        L4e:
            boolean r1 = r0.containsKey(r4)
            if (r1 != 0) goto L73
            com.facebook.o r1 = com.facebook.o.a
            com.facebook.internal.AbstractC1554i.k()
            java.lang.String r1 = com.facebook.o.f
            if (r1 == 0) goto L6b
            boolean r1 = com.facebook.internal.J.D(r1)
            if (r1 == 0) goto L73
            java.lang.String r1 = "t"
            java.lang.String r2 = "Starting with v13 of the SDK, a client token must be embedded in your client code before making Graph API calls. Visit https://developers.facebook.com/docs/android/getting-started#client-token to learn how to implement this change."
            android.util.Log.w(r1, r2)
            goto L73
        L6b:
            com.facebook.FacebookException r0 = new com.facebook.FacebookException
            java.lang.String r1 = "A valid Facebook client token must be set in the AndroidManifest.xml or set by calling FacebookSdk.setClientToken before initializing the sdk. Visit https://developers.facebook.com/docs/android/getting-started#add-app_id for more information."
            r0.<init>(r1)
            throw r0
        L73:
            java.lang.String r1 = "sdk"
            java.lang.String r2 = "android"
            r0.putString(r1, r2)
            java.lang.String r1 = "format"
            java.lang.String r2 = "json"
            r0.putString(r1, r2)
            com.facebook.y r0 = com.facebook.y.g
            com.facebook.o.h(r0)
            com.facebook.y r0 = com.facebook.y.f
            com.facebook.o.h(r0)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.facebook.t.a():void");
    }

    public final String b(String str, boolean z) {
        if (!z && this.h == x.b) {
            return str;
        }
        Uri.Builder builderBuildUpon = Uri.parse(str).buildUpon();
        for (String str2 : this.d.keySet()) {
            Object obj = this.d.get(str2);
            if (obj == null) {
                obj = "";
            }
            if (assistantMode.utils.studiableMetadata.b.N(obj)) {
                builderBuildUpon.appendQueryParameter(str2, assistantMode.utils.studiableMetadata.b.C(obj).toString());
            } else if (this.h != x.a) {
                String str3 = String.format(Locale.US, "Unsupported parameter type for GET request: %s", Arrays.copyOf(new Object[]{obj.getClass().getSimpleName()}, 1));
                Intrinsics.checkNotNullExpressionValue(str3, "format(locale, format, *args)");
                throw new IllegalArgumentException(str3);
            }
        }
        String string = builderBuildUpon.toString();
        Intrinsics.checkNotNullExpressionValue(string, "uriBuilder.toString()");
        return string;
    }

    public final w c() throws Throwable {
        Intrinsics.checkNotNullParameter(this, "request");
        t[] requests = {this};
        Intrinsics.checkNotNullParameter(requests, "requests");
        List requests2 = C4933y.P(requests);
        Intrinsics.checkNotNullParameter(requests2, "requests");
        ArrayList arrayListH = assistantMode.utils.studiableMetadata.b.H(new v(requests2));
        if (arrayListH.size() == 1) {
            return (w) arrayListH.get(0);
        }
        throw new FacebookException("invalid state: expected a single response");
    }

    public final u d() {
        t[] requests = {this};
        Intrinsics.checkNotNullParameter(requests, "requests");
        List requests2 = C4933y.P(requests);
        Intrinsics.checkNotNullParameter(requests2, "requests");
        v requests3 = new v(requests2);
        Intrinsics.checkNotNullParameter(requests3, "requests");
        AbstractC1554i.i(requests3);
        u uVar = new u(requests3);
        uVar.executeOnExecutor(o.c(), new Void[0]);
        return uVar;
    }

    public final String e() {
        AccessToken accessToken = this.a;
        if (accessToken != null) {
            if (!this.d.containsKey("access_token")) {
                com.google.mlkit.common.sdkinternal.model.a aVar = com.facebook.internal.A.c;
                String str = accessToken.e;
                aVar.y(str);
                return str;
            }
        } else if (!this.d.containsKey("access_token")) {
            return f();
        }
        return this.d.getString("access_token");
    }

    public final String g() {
        String strS;
        String str;
        if (this.h == x.b && (str = this.b) != null && D.k(str, "/videos", false)) {
            strS = d0.s(new Object[]{o.e()}, 1, "https://graph-video.%s", "format(format, *args)");
        } else {
            String subdomain = o.e();
            Intrinsics.checkNotNullParameter(subdomain, "subdomain");
            strS = d0.s(new Object[]{subdomain}, 1, "https://graph.%s", "format(format, *args)");
        }
        String strH = h(strS);
        a();
        return b(strH, false);
    }

    public final String h(String str) {
        if (!(!Intrinsics.b(o.e(), "instagram.com") ? true : !i())) {
            str = d0.s(new Object[]{o.q}, 1, "https://graph.%s", "format(format, *args)");
        }
        Pattern pattern = k;
        String strS = this.b;
        if (!pattern.matcher(strS).matches()) {
            strS = d0.s(new Object[]{this.f, strS}, 2, "%s/%s", "format(format, *args)");
        }
        return d0.s(new Object[]{str, strS}, 2, "%s/%s", "format(format, *args)");
    }

    public final boolean i() {
        String str = this.b;
        if (str == null) {
            return false;
        }
        StringBuilder sb = new StringBuilder("^/?");
        sb.append(o.b());
        sb.append("/?.*");
        return this.i || Pattern.matches(sb.toString(), str) || Pattern.matches("^/?app/?.*", str);
    }

    public final void j(q qVar) {
        o.h(y.g);
        o.h(y.f);
        this.g = qVar;
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("{Request:  accessToken: ");
        Object obj = this.a;
        if (obj == null) {
            obj = "null";
        }
        sb.append(obj);
        sb.append(", graphPath: ");
        sb.append(this.b);
        sb.append(", graphObject: ");
        sb.append(this.c);
        sb.append(", httpMethod: ");
        sb.append(this.h);
        sb.append(", parameters: ");
        sb.append(this.d);
        sb.append("}");
        String string = sb.toString();
        Intrinsics.checkNotNullExpressionValue(string, "StringBuilder()\n        …(\"}\")\n        .toString()");
        return string;
    }
}

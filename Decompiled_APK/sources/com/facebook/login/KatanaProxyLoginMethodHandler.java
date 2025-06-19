package com.facebook.login;

import android.content.Intent;
import android.os.Parcel;
import android.os.Parcelable;
import com.facebook.internal.AbstractC1554i;
import com.facebook.login.LoginClient;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Set;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.json.JSONException;
import org.json.JSONObject;

@Metadata
/* loaded from: classes.dex */
public final class KatanaProxyLoginMethodHandler extends NativeAppLoginMethodHandler {

    @NotNull
    public static final Parcelable.Creator<KatanaProxyLoginMethodHandler> CREATOR = new C1565b(4);
    public final String d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public KatanaProxyLoginMethodHandler(LoginClient loginClient) {
        super(loginClient);
        Intrinsics.checkNotNullParameter(loginClient, "loginClient");
        this.d = "katana_proxy_auth";
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    @Override // com.facebook.login.LoginMethodHandler
    public final String f() {
        return this.d;
    }

    @Override // com.facebook.login.LoginMethodHandler
    public final int m(LoginClient.Request request) throws JSONException {
        boolean z;
        Intrinsics.checkNotNullParameter(request, "request");
        boolean z2 = com.facebook.o.m && AbstractC1554i.c() != null && request.a.e;
        JSONObject jSONObject = new JSONObject();
        try {
            jSONObject.put("init", System.currentTimeMillis());
        } catch (JSONException unused) {
        }
        String e2e = jSONObject.toString();
        Intrinsics.checkNotNullExpressionValue(e2e, "e2e.toString()");
        d().f();
        String applicationId = request.d;
        Set set = request.b;
        Set permissions = set;
        Iterator it2 = set.iterator();
        while (true) {
            if (!it2.hasNext()) {
                z = false;
                break;
            }
            String str = (String) it2.next();
            y yVar = B.b;
            if (y.b(str)) {
                z = true;
                break;
            }
        }
        EnumC1567d enumC1567d = request.c;
        if (enumC1567d == null) {
            enumC1567d = EnumC1567d.NONE;
        }
        EnumC1567d defaultAudience = enumC1567d;
        String clientState = c(request.e);
        String authType = request.h;
        String str2 = request.j;
        boolean z3 = request.k;
        boolean z4 = request.m;
        boolean z5 = request.n;
        String str3 = request.o;
        EnumC1564a enumC1564a = request.r;
        if (enumC1564a != null) {
            enumC1564a.name();
        }
        com.facebook.internal.C c = com.facebook.internal.C.a;
        ArrayList<Intent> arrayList = null;
        if (!com.facebook.internal.instrument.crashshield.a.b(com.facebook.internal.C.class)) {
            try {
                Intrinsics.checkNotNullParameter(applicationId, "applicationId");
                Intrinsics.checkNotNullParameter(permissions, "permissions");
                Intrinsics.checkNotNullParameter(e2e, "e2e");
                Intrinsics.checkNotNullParameter(defaultAudience, "defaultAudience");
                Intrinsics.checkNotNullParameter(clientState, "clientState");
                Intrinsics.checkNotNullParameter(authType, "authType");
                ArrayList arrayList2 = com.facebook.internal.C.b;
                ArrayList arrayList3 = new ArrayList();
                Iterator it3 = arrayList2.iterator();
                while (it3.hasNext()) {
                    boolean z6 = z4;
                    String str4 = str3;
                    boolean z7 = z5;
                    boolean z8 = z3;
                    Intent intentC = com.facebook.internal.C.a.c((com.facebook.internal.B) it3.next(), applicationId, permissions, e2e, z, defaultAudience, clientState, authType, z2, str2, z8, D.FACEBOOK, z6, z7, str4);
                    if (intentC != null) {
                        arrayList3.add(intentC);
                    }
                    z3 = z8;
                    z4 = z6;
                    z5 = z7;
                    str3 = str4;
                }
                arrayList = arrayList3;
            } catch (Throwable th) {
                com.facebook.internal.instrument.crashshield.a.a(com.facebook.internal.C.class, th);
            }
        }
        a("e2e", e2e);
        int i = 0;
        for (Intent intent : arrayList) {
            i++;
            assistantMode.refactored.a.a(1);
            if (r(intent)) {
                return i;
            }
        }
        return 0;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public KatanaProxyLoginMethodHandler(Parcel source) {
        super(source);
        Intrinsics.checkNotNullParameter(source, "source");
        this.d = "katana_proxy_auth";
    }
}

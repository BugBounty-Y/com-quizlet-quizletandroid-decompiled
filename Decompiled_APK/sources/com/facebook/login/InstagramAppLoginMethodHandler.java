package com.facebook.login;

import android.content.Context;
import android.content.Intent;
import android.content.pm.ResolveInfo;
import android.os.Parcel;
import android.os.Parcelable;
import com.facebook.internal.AbstractC1559n;
import com.facebook.login.LoginClient;
import java.util.Iterator;
import java.util.Set;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.json.JSONException;
import org.json.JSONObject;

@Metadata
/* loaded from: classes.dex */
public final class InstagramAppLoginMethodHandler extends NativeAppLoginMethodHandler {

    @NotNull
    public static final Parcelable.Creator<InstagramAppLoginMethodHandler> CREATOR = new C1565b(3);
    public final String d;
    public final com.facebook.g e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public InstagramAppLoginMethodHandler(LoginClient loginClient) {
        super(loginClient);
        Intrinsics.checkNotNullParameter(loginClient, "loginClient");
        this.d = "instagram_login";
        this.e = com.facebook.g.INSTAGRAM_APPLICATION_WEB;
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
        ResolveInfo resolveInfoResolveActivity;
        Intrinsics.checkNotNullParameter(request, "request");
        JSONObject jSONObject = new JSONObject();
        try {
            jSONObject.put("init", System.currentTimeMillis());
        } catch (JSONException unused) {
        }
        String e2e = jSONObject.toString();
        Intrinsics.checkNotNullExpressionValue(e2e, "e2e.toString()");
        Context context = d().f();
        if (context == null) {
            context = com.facebook.o.a();
        }
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
        boolean z2 = request.k;
        boolean z3 = request.m;
        boolean z4 = request.n;
        com.facebook.internal.C c = com.facebook.internal.C.a;
        Intent intent = null;
        if (!com.facebook.internal.instrument.crashshield.a.b(com.facebook.internal.C.class)) {
            try {
                Intrinsics.checkNotNullParameter(context, "context");
                Intrinsics.checkNotNullParameter(applicationId, "applicationId");
                Intrinsics.checkNotNullParameter(permissions, "permissions");
                Intrinsics.checkNotNullParameter(e2e, "e2e");
                Intrinsics.checkNotNullParameter(defaultAudience, "defaultAudience");
                Intrinsics.checkNotNullParameter(clientState, "clientState");
                Intrinsics.checkNotNullParameter(authType, "authType");
                Intent intentC = com.facebook.internal.C.a.c(new com.facebook.internal.B(1), applicationId, permissions, e2e, z, defaultAudience, clientState, authType, false, str2, z2, D.INSTAGRAM, z3, z4, "");
                if (!com.facebook.internal.instrument.crashshield.a.b(com.facebook.internal.C.class)) {
                    try {
                        Intrinsics.checkNotNullParameter(context, "context");
                        if (intentC != null && (resolveInfoResolveActivity = context.getPackageManager().resolveActivity(intentC, 0)) != null) {
                            String str3 = resolveInfoResolveActivity.activityInfo.packageName;
                            Intrinsics.checkNotNullExpressionValue(str3, "resolveInfo.activityInfo.packageName");
                            if (AbstractC1559n.a(context, str3)) {
                                intent = intentC;
                            }
                        }
                    } catch (Throwable th) {
                        com.facebook.internal.instrument.crashshield.a.a(com.facebook.internal.C.class, th);
                    }
                }
            } catch (Throwable th2) {
                com.facebook.internal.instrument.crashshield.a.a(com.facebook.internal.C.class, th2);
            }
        }
        Intent intent2 = intent;
        a("e2e", e2e);
        assistantMode.refactored.a.a(1);
        return r(intent2) ? 1 : 0;
    }

    @Override // com.facebook.login.NativeAppLoginMethodHandler
    public final com.facebook.g o() {
        return this.e;
    }

    @Override // com.facebook.login.LoginMethodHandler, android.os.Parcelable
    public final void writeToParcel(Parcel dest, int i) {
        Intrinsics.checkNotNullParameter(dest, "dest");
        super.writeToParcel(dest, i);
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public InstagramAppLoginMethodHandler(Parcel source) {
        super(source);
        Intrinsics.checkNotNullParameter(source, "source");
        this.d = "instagram_login";
        this.e = com.facebook.g.INSTAGRAM_APPLICATION_WEB;
    }
}

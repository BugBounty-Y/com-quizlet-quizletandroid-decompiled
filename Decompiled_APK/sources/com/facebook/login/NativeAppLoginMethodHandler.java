package com.facebook.login;

import android.content.Intent;
import android.content.pm.ResolveInfo;
import android.os.Bundle;
import android.os.Parcel;
import android.text.TextUtils;
import com.facebook.FacebookException;
import com.facebook.internal.J;
import com.facebook.login.LoginClient;
import com.google.android.gms.internal.mlkit_vision_common.J2;
import java.util.ArrayList;
import java.util.List;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
public abstract class NativeAppLoginMethodHandler extends LoginMethodHandler {
    public final com.facebook.g c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public NativeAppLoginMethodHandler(LoginClient loginClient) {
        super(loginClient);
        Intrinsics.checkNotNullParameter(loginClient, "loginClient");
        this.c = com.facebook.g.FACEBOOK_APPLICATION_WEB;
    }

    @Override // com.facebook.login.LoginMethodHandler
    public final boolean i(int i, int i2, Intent data) {
        String string;
        String string2;
        Object obj;
        LoginClient.Request request = d().g;
        q qVar = q.CANCEL;
        if (data == null) {
            n(new LoginClient.Result(request, qVar, null, "Operation canceled", null));
            return true;
        }
        q qVar2 = q.ERROR;
        if (i2 == 0) {
            Intrinsics.checkNotNullParameter(data, "data");
            Bundle extras = data.getExtras();
            if (extras == null || (string = extras.getString("error")) == null) {
                string = extras != null ? extras.getString("error_type") : null;
            }
            String string3 = (extras == null || (obj = extras.get("error_code")) == null) ? null : obj.toString();
            if (!"CONNECTION_FAILURE".equals(string3)) {
                n(new LoginClient.Result(request, qVar, null, string, null));
                return true;
            }
            if (extras != null && (string2 = extras.getString("error_message")) != null) {
                string = string2;
            } else if (extras != null) {
                string = extras.getString("error_description");
            }
            ArrayList arrayList = new ArrayList();
            if (string != null) {
                arrayList.add(string);
            }
            if (string != null) {
                arrayList.add(string);
            }
            n(new LoginClient.Result(request, qVar2, null, TextUtils.join(": ", arrayList), string3));
            return true;
        }
        if (i2 != -1) {
            ArrayList arrayList2 = new ArrayList();
            arrayList2.add("Unexpected resultCode from authorization.");
            n(new LoginClient.Result(request, qVar2, null, TextUtils.join(": ", arrayList2), null));
            return true;
        }
        Bundle extras2 = data.getExtras();
        if (extras2 == null) {
            ArrayList arrayList3 = new ArrayList();
            arrayList3.add("Unexpected null from returned authorization data.");
            n(new LoginClient.Result(request, qVar2, null, TextUtils.join(": ", arrayList3), null));
            return true;
        }
        String string4 = extras2.getString("error");
        if (string4 == null) {
            string4 = extras2.getString("error_type");
        }
        Object obj2 = extras2.get("error_code");
        string = obj2 != null ? obj2.toString() : null;
        String string5 = extras2.getString("error_message");
        if (string5 == null) {
            string5 = extras2.getString("error_description");
        }
        String string6 = extras2.getString("e2e");
        if (!J.D(string6)) {
            h(string6);
        }
        if (string4 != null || string != null || string5 != null || request == null) {
            p(request, string4, string5, string);
            return true;
        }
        if (!extras2.containsKey("code") || J.D(extras2.getString("code"))) {
            q(request, extras2);
            return true;
        }
        com.facebook.o.c().execute(new E(this, request, extras2, 0));
        return true;
    }

    public final void n(LoginClient.Result result) {
        if (result != null) {
            d().d(result);
        } else {
            d().l();
        }
    }

    public com.facebook.g o() {
        return this.c;
    }

    public final void p(LoginClient.Request request, String str, String str2, String str3) {
        if (str != null && str.equals("logged_out")) {
            CustomTabLoginMethodHandler.i = true;
            n(null);
            return;
        }
        if (CollectionsKt.F(kotlin.collections.B.j("service_disabled", "AndroidAuthKillSwitchException"), str)) {
            n(null);
            return;
        }
        if (CollectionsKt.F(kotlin.collections.B.j("access_denied", "OAuthAccessDeniedException"), str)) {
            n(new LoginClient.Result(request, q.CANCEL, null, null, null));
            return;
        }
        ArrayList arrayList = new ArrayList();
        if (str != null) {
            arrayList.add(str);
        }
        if (str2 != null) {
            arrayList.add(str2);
        }
        n(new LoginClient.Result(request, q.ERROR, null, TextUtils.join(": ", arrayList), str3));
    }

    public final void q(LoginClient.Request request, Bundle extras) {
        Intrinsics.checkNotNullParameter(request, "request");
        Intrinsics.checkNotNullParameter(extras, "extras");
        try {
            n(new LoginClient.Result(request, q.SUCCESS, J2.c(request.b, extras, o(), request.d), J2.d(extras, request.o), null, null));
        } catch (FacebookException e) {
            String message = e.getMessage();
            ArrayList arrayList = new ArrayList();
            if (message != null) {
                arrayList.add(message);
            }
            n(new LoginClient.Result(request, q.ERROR, null, TextUtils.join(": ", arrayList), null));
        }
    }

    public final boolean r(Intent intent) {
        if (intent == null) {
            return false;
        }
        List<ResolveInfo> listQueryIntentActivities = com.facebook.o.a().getPackageManager().queryIntentActivities(intent, 65536);
        Intrinsics.checkNotNullExpressionValue(listQueryIntentActivities, "getApplicationContext()\n…nager.MATCH_DEFAULT_ONLY)");
        if (listQueryIntentActivities.isEmpty()) {
            return false;
        }
        u uVar = d().c;
        Unit unit = null;
        if (uVar == null) {
            uVar = null;
        }
        if (uVar != null) {
            androidx.activity.result.b bVar = uVar.d;
            if (bVar == null) {
                Intrinsics.m("launcher");
                throw null;
            }
            bVar.a(intent);
            unit = Unit.a;
        }
        return unit != null;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public NativeAppLoginMethodHandler(Parcel source) {
        super(source);
        Intrinsics.checkNotNullParameter(source, "source");
        this.c = com.facebook.g.FACEBOOK_APPLICATION_WEB;
    }
}

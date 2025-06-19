package com.facebook.login;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.text.TextUtils;
import com.facebook.AccessToken;
import com.facebook.FacebookActivity;
import com.facebook.FacebookException;
import com.facebook.internal.AbstractC1554i;
import com.facebook.internal.C1553h;
import com.facebook.internal.InterfaceC1552g;
import com.facebook.login.LoginClient;
import com.google.android.gms.internal.mlkit_vision_common.K2;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import kotlin.collections.C4933y;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class B {
    public static final y b = new y();
    public static final Set c;
    public static final String d;
    public static volatile B e;
    public final SharedPreferences a;

    static {
        String[] elements = {"ads_management", "create_event", "rsvp_event"};
        Intrinsics.checkNotNullParameter(elements, "elements");
        c = C4933y.T(elements);
        String string = B.class.toString();
        Intrinsics.checkNotNullExpressionValue(string, "LoginManager::class.java.toString()");
        d = string;
    }

    public B() {
        AbstractC1554i.k();
        SharedPreferences sharedPreferences = com.facebook.o.a().getSharedPreferences("com.facebook.loginManager", 0);
        Intrinsics.checkNotNullExpressionValue(sharedPreferences, "getApplicationContext().…ER, Context.MODE_PRIVATE)");
        this.a = sharedPreferences;
        if (!com.facebook.o.l || AbstractC1554i.c() == null) {
            return;
        }
        androidx.browser.customtabs.l.a(com.facebook.o.a(), "com.android.chrome", new C1566c());
        Context contextA = com.facebook.o.a();
        String packageName = com.facebook.o.a().getPackageName();
        if (packageName == null) {
            return;
        }
        Context applicationContext = contextA.getApplicationContext();
        try {
            androidx.browser.customtabs.l.a(applicationContext, packageName, new androidx.browser.customtabs.b(applicationContext));
        } catch (SecurityException unused) {
        }
    }

    public static LoginClient.Request a(com.quizlet.data.repository.folderwithcreator.e loginConfig) {
        String strB = (String) loginConfig.d;
        Intrinsics.checkNotNullParameter(loginConfig, "loginConfig");
        EnumC1564a enumC1564a = EnumC1564a.a;
        try {
            strB = K2.b(strB);
        } catch (FacebookException unused) {
            enumC1564a = EnumC1564a.b;
        }
        LoginClient.Request request = new LoginClient.Request(CollectionsKt.A0((Set) loginConfig.b), com.facebook.o.b(), androidx.compose.ui.node.B.f("randomUUID().toString()"), (String) loginConfig.c, (String) loginConfig.d, strB, enumC1564a);
        Date date = AccessToken.l;
        request.f = com.google.android.gms.internal.mlkit_vision_common.D.d();
        request.j = null;
        request.k = false;
        request.m = false;
        request.n = false;
        return request;
    }

    public static Intent b(LoginClient.Request request) {
        Intrinsics.checkNotNullParameter(request, "request");
        Intent intent = new Intent();
        intent.setClass(com.facebook.o.a(), FacebookActivity.class);
        intent.setAction(request.a.toString());
        Bundle bundle = new Bundle();
        bundle.putParcelable("request", request);
        intent.putExtra("com.facebook.LoginFragment:Request", bundle);
        return intent;
    }

    public static void c(Context context, q qVar, Map map, FacebookException facebookException, boolean z, LoginClient.Request request) {
        v vVarC = A.a.c(context);
        if (vVarC == null) {
            return;
        }
        if (request == null) {
            ScheduledExecutorService scheduledExecutorService = v.d;
            if (com.facebook.internal.instrument.crashshield.a.b(v.class)) {
                return;
            }
            try {
                vVarC.a("fb_mobile_login_complete", "");
                return;
            } catch (Throwable th) {
                com.facebook.internal.instrument.crashshield.a.a(v.class, th);
                return;
            }
        }
        HashMap loggingExtras = new HashMap();
        loggingExtras.put("try_login_activity", z ? "1" : "0");
        String str = request.e;
        String str2 = request.m ? "foa_mobile_login_complete" : "fb_mobile_login_complete";
        if (com.facebook.internal.instrument.crashshield.a.b(vVarC)) {
            return;
        }
        try {
            Intrinsics.checkNotNullParameter(loggingExtras, "loggingExtras");
            ScheduledExecutorService scheduledExecutorService2 = v.d;
            Bundle bundleB = A.b(str);
            if (qVar != null) {
                bundleB.putString("2_result", qVar.a);
            }
            if ((facebookException != null ? facebookException.getMessage() : null) != null) {
                bundleB.putString("5_error_message", facebookException.getMessage());
            }
            JSONObject jSONObject = loggingExtras.isEmpty() ? null : new JSONObject(loggingExtras);
            if (map != null) {
                if (jSONObject == null) {
                    jSONObject = new JSONObject();
                }
                try {
                    for (Map.Entry entry : map.entrySet()) {
                        String str3 = (String) entry.getKey();
                        String str4 = (String) entry.getValue();
                        if (str3 != null) {
                            jSONObject.put(str3, str4);
                        }
                    }
                } catch (JSONException unused) {
                }
            }
            if (jSONObject != null) {
                bundleB.putString("6_extras", jSONObject.toString());
            }
            vVarC.b.b(bundleB, str2);
            if (qVar != q.SUCCESS || com.facebook.internal.instrument.crashshield.a.b(vVarC)) {
                return;
            }
            try {
                v.d.schedule(new androidx.credentials.playservices.controllers.c(24, vVarC, A.b(str)), 5L, TimeUnit.SECONDS);
            } catch (Throwable th2) {
                com.facebook.internal.instrument.crashshield.a.a(vVarC, th2);
            }
        } catch (Throwable th3) {
            com.facebook.internal.instrument.crashshield.a.a(vVarC, th3);
        }
    }

    public static void d(Context context, LoginClient.Request pendingLoginRequest) {
        v vVarC = A.a.c(context);
        if (vVarC != null) {
            String str = pendingLoginRequest.m ? "foa_mobile_login_start" : "fb_mobile_login_start";
            if (com.facebook.internal.instrument.crashshield.a.b(vVarC)) {
                return;
            }
            try {
                Intrinsics.checkNotNullParameter(pendingLoginRequest, "pendingLoginRequest");
                ScheduledExecutorService scheduledExecutorService = v.d;
                Bundle bundleB = A.b(pendingLoginRequest.e);
                try {
                    JSONObject jSONObject = new JSONObject();
                    jSONObject.put("login_behavior", pendingLoginRequest.a.toString());
                    jSONObject.put("request_code", assistantMode.refactored.a.a(1));
                    jSONObject.put("permissions", TextUtils.join(",", pendingLoginRequest.b));
                    jSONObject.put("default_audience", pendingLoginRequest.c.toString());
                    jSONObject.put("isReauthorize", pendingLoginRequest.f);
                    String str2 = vVarC.c;
                    if (str2 != null) {
                        jSONObject.put("facebookVersion", str2);
                    }
                    D d2 = pendingLoginRequest.l;
                    if (d2 != null) {
                        jSONObject.put("target_app", d2.a);
                    }
                    bundleB.putString("6_extras", jSONObject.toString());
                } catch (JSONException unused) {
                }
                vVarC.b.b(bundleB, str);
            } catch (Throwable th) {
                com.facebook.internal.instrument.crashshield.a.a(vVarC, th);
            }
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:20:0x0055  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void e(int r11, android.content.Intent r12, com.facebook.l r13) {
        /*
            Method dump skipped, instructions count: 268
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.facebook.login.B.e(int, android.content.Intent, com.facebook.l):void");
    }

    public final void f(com.facebook.j jVar, final com.facebook.l lVar) {
        if (!(jVar instanceof C1553h)) {
            throw new FacebookException("Unexpected CallbackManager, please use the provided Factory.");
        }
        C1553h c1553h = (C1553h) jVar;
        int iA = assistantMode.refactored.a.a(1);
        InterfaceC1552g callback = new InterfaceC1552g() { // from class: com.facebook.login.w
            @Override // com.facebook.internal.InterfaceC1552g
            public final void a(int i, Intent intent) {
                B this$0 = this.a;
                Intrinsics.checkNotNullParameter(this$0, "this$0");
                this$0.e(i, intent, lVar);
            }
        };
        c1553h.getClass();
        Intrinsics.checkNotNullParameter(callback, "callback");
        c1553h.a.put(Integer.valueOf(iA), callback);
    }
}

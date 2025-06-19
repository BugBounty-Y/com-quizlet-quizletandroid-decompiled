package com.facebook.login;

import android.content.Intent;
import android.os.Bundle;
import android.os.Parcel;
import android.os.Parcelable;
import android.text.TextUtils;
import androidx.fragment.app.I;
import com.facebook.AccessToken;
import com.facebook.AuthenticationToken;
import com.facebook.CustomTabMainActivity;
import com.facebook.internal.AbstractC1554i;
import com.facebook.internal.J;
import com.quizlet.quizletandroid.R;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ScheduledExecutorService;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.json.JSONObject;

@Metadata
/* loaded from: classes.dex */
public class LoginClient implements Parcelable {

    @NotNull
    public static final Parcelable.Creator<LoginClient> CREATOR = new C1565b(5);
    public LoginMethodHandler[] a;
    public int b;
    public u c;
    public s d;
    public androidx.webkit.internal.p e;
    public boolean f;
    public Request g;
    public Map h;
    public LinkedHashMap i;
    public v j;
    public int k;
    public int l;

    @Metadata
    public static final class Result implements Parcelable {

        @NotNull
        public static final Parcelable.Creator<Result> CREATOR = new r();
        public final q a;
        public final AccessToken b;
        public final AuthenticationToken c;
        public final String d;
        public final String e;
        public final Request f;
        public Map g;
        public HashMap h;

        /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
        public Result(Request request, q code, AccessToken accessToken, String str, String str2) {
            this(request, code, accessToken, null, str, str2);
            Intrinsics.checkNotNullParameter(code, "code");
        }

        @Override // android.os.Parcelable
        public final int describeContents() {
            return 0;
        }

        @Override // android.os.Parcelable
        public final void writeToParcel(Parcel dest, int i) {
            Intrinsics.checkNotNullParameter(dest, "dest");
            dest.writeString(this.a.name());
            dest.writeParcelable(this.b, i);
            dest.writeParcelable(this.c, i);
            dest.writeString(this.d);
            dest.writeString(this.e);
            dest.writeParcelable(this.f, i);
            J.P(dest, this.g);
            J.P(dest, this.h);
        }

        public Result(Request request, q code, AccessToken accessToken, AuthenticationToken authenticationToken, String str, String str2) {
            Intrinsics.checkNotNullParameter(code, "code");
            this.f = request;
            this.b = accessToken;
            this.c = authenticationToken;
            this.d = str;
            this.a = code;
            this.e = str2;
        }

        public Result(Parcel parcel) {
            String string = parcel.readString();
            this.a = q.valueOf(string == null ? "error" : string);
            this.b = (AccessToken) parcel.readParcelable(AccessToken.class.getClassLoader());
            this.c = (AuthenticationToken) parcel.readParcelable(AuthenticationToken.class.getClassLoader());
            this.d = parcel.readString();
            this.e = parcel.readString();
            this.f = (Request) parcel.readParcelable(Request.class.getClassLoader());
            this.g = J.K(parcel);
            this.h = J.K(parcel);
        }
    }

    public final void a(String str, String str2, boolean z) {
        Map map = this.h;
        if (map == null) {
            map = new HashMap();
        }
        if (this.h == null) {
            this.h = map;
        }
        if (map.containsKey(str) && z) {
            str2 = ((String) map.get(str)) + ',' + str2;
        }
        map.put(str, str2);
    }

    public final boolean b() {
        if (this.f) {
            return true;
        }
        Intrinsics.checkNotNullParameter("android.permission.INTERNET", "permission");
        I iF = f();
        if ((iF != null ? iF.checkCallingOrSelfPermission("android.permission.INTERNET") : -1) == 0) {
            this.f = true;
            return true;
        }
        I iF2 = f();
        String string = iF2 != null ? iF2.getString(R.string.com_facebook_internet_permission_error_title) : null;
        String string2 = iF2 != null ? iF2.getString(R.string.com_facebook_internet_permission_error_message) : null;
        Request request = this.g;
        ArrayList arrayList = new ArrayList();
        if (string != null) {
            arrayList.add(string);
        }
        if (string2 != null) {
            arrayList.add(string2);
        }
        c(new Result(request, q.ERROR, null, TextUtils.join(": ", arrayList), null));
        return false;
    }

    public final void c(Result outcome) {
        LoginClient loginClient;
        Intrinsics.checkNotNullParameter(outcome, "outcome");
        LoginMethodHandler loginMethodHandlerG = g();
        if (loginMethodHandlerG != null) {
            loginClient = this;
            loginClient.i(loginMethodHandlerG.f(), outcome.a.a, outcome.d, outcome.e, loginMethodHandlerG.a);
        } else {
            loginClient = this;
        }
        Map map = loginClient.h;
        if (map != null) {
            outcome.g = map;
        }
        LinkedHashMap linkedHashMap = loginClient.i;
        if (linkedHashMap != null) {
            outcome.h = linkedHashMap;
        }
        loginClient.a = null;
        loginClient.b = -1;
        loginClient.g = null;
        loginClient.h = null;
        loginClient.k = 0;
        loginClient.l = 0;
        s sVar = loginClient.d;
        if (sVar != null) {
            u this$0 = sVar.a;
            Intrinsics.checkNotNullParameter(this$0, "this$0");
            Intrinsics.checkNotNullParameter(outcome, "outcome");
            this$0.b = null;
            int i = outcome.a == q.CANCEL ? 0 : -1;
            Bundle bundle = new Bundle();
            bundle.putParcelable("com.facebook.LoginFragment:Result", outcome);
            Intent intent = new Intent();
            intent.putExtras(bundle);
            I activity = this$0.getActivity();
            if (!this$0.isAdded() || activity == null) {
                return;
            }
            activity.setResult(i, intent);
            activity.finish();
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:15:0x0046 A[Catch: Exception -> 0x0044, TryCatch #0 {Exception -> 0x0044, blocks: (B:10:0x0028, B:12:0x0032, B:16:0x005e, B:15:0x0046), top: B:27:0x0028 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void d(com.facebook.login.LoginClient.Result r19) {
        /*
            r18 = this;
            r1 = r18
            r0 = r19
            java.lang.String r2 = "outcome"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r0, r2)
            com.facebook.AccessToken r2 = r0.b
            if (r2 == 0) goto L8e
            java.util.Date r2 = com.facebook.AccessToken.l
            boolean r2 = com.google.android.gms.internal.mlkit_vision_common.D.d()
            if (r2 == 0) goto L8e
            java.lang.String r2 = "pendingResult"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r0, r2)
            com.facebook.AccessToken r2 = r0.b
            if (r2 == 0) goto L86
            com.facebook.AccessToken r3 = com.google.android.gms.internal.mlkit_vision_common.D.c()
            com.facebook.login.q r6 = com.facebook.login.q.ERROR
            java.lang.String r10 = ": "
            if (r3 == 0) goto L46
            java.lang.String r3 = r3.i     // Catch: java.lang.Exception -> L44
            java.lang.String r2 = r2.i     // Catch: java.lang.Exception -> L44
            boolean r2 = kotlin.jvm.internal.Intrinsics.b(r3, r2)     // Catch: java.lang.Exception -> L44
            if (r2 == 0) goto L46
            com.facebook.login.LoginClient$Request r12 = r1.g     // Catch: java.lang.Exception -> L44
            com.facebook.AccessToken r14 = r0.b     // Catch: java.lang.Exception -> L44
            com.facebook.AuthenticationToken r15 = r0.c     // Catch: java.lang.Exception -> L44
            com.facebook.login.LoginClient$Result r11 = new com.facebook.login.LoginClient$Result     // Catch: java.lang.Exception -> L44
            com.facebook.login.q r13 = com.facebook.login.q.SUCCESS     // Catch: java.lang.Exception -> L44
            r16 = 0
            r17 = 0
            r11.<init>(r12, r13, r14, r15, r16, r17)     // Catch: java.lang.Exception -> L44
            goto L5e
        L44:
            r0 = move-exception
            goto L62
        L46:
            com.facebook.login.LoginClient$Request r5 = r1.g     // Catch: java.lang.Exception -> L44
            java.lang.String r0 = "User logged in as different Facebook user."
            java.util.ArrayList r2 = new java.util.ArrayList     // Catch: java.lang.Exception -> L44
            r2.<init>()     // Catch: java.lang.Exception -> L44
            r2.add(r0)     // Catch: java.lang.Exception -> L44
            java.lang.String r8 = android.text.TextUtils.join(r10, r2)     // Catch: java.lang.Exception -> L44
            com.facebook.login.LoginClient$Result r4 = new com.facebook.login.LoginClient$Result     // Catch: java.lang.Exception -> L44
            r7 = 0
            r9 = 0
            r4.<init>(r5, r6, r7, r8, r9)     // Catch: java.lang.Exception -> L44
            r11 = r4
        L5e:
            r1.c(r11)     // Catch: java.lang.Exception -> L44
            return
        L62:
            com.facebook.login.LoginClient$Request r5 = r1.g
            java.lang.String r0 = r0.getMessage()
            java.util.ArrayList r2 = new java.util.ArrayList
            r2.<init>()
            java.lang.String r3 = "Caught exception"
            r2.add(r3)
            if (r0 == 0) goto L77
            r2.add(r0)
        L77:
            java.lang.String r8 = android.text.TextUtils.join(r10, r2)
            com.facebook.login.LoginClient$Result r4 = new com.facebook.login.LoginClient$Result
            r7 = 0
            r9 = 0
            r4.<init>(r5, r6, r7, r8, r9)
            r1.c(r4)
            return
        L86:
            com.facebook.FacebookException r0 = new com.facebook.FacebookException
            java.lang.String r2 = "Can't validate without a token"
            r0.<init>(r2)
            throw r0
        L8e:
            r18.c(r19)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.facebook.login.LoginClient.d(com.facebook.login.LoginClient$Result):void");
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    public final I f() {
        u uVar = this.c;
        if (uVar != null) {
            return uVar.getActivity();
        }
        return null;
    }

    public final LoginMethodHandler g() {
        LoginMethodHandler[] loginMethodHandlerArr;
        int i = this.b;
        if (i < 0 || (loginMethodHandlerArr = this.a) == null) {
            return null;
        }
        return loginMethodHandlerArr[i];
    }

    /* JADX WARN: Removed duplicated region for block: B:13:0x0019  */
    /* JADX WARN: Removed duplicated region for block: B:16:0x0021  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final com.facebook.login.v h() {
        /*
            r4 = this;
            com.facebook.login.v r0 = r4.j
            if (r0 == 0) goto L21
            boolean r1 = com.facebook.internal.instrument.crashshield.a.b(r0)
            r2 = 0
            if (r1 == 0) goto Ld
        Lb:
            r1 = r2
            goto L15
        Ld:
            java.lang.String r1 = r0.a     // Catch: java.lang.Throwable -> L10
            goto L15
        L10:
            r1 = move-exception
            com.facebook.internal.instrument.crashshield.a.a(r0, r1)
            goto Lb
        L15:
            com.facebook.login.LoginClient$Request r3 = r4.g
            if (r3 == 0) goto L1b
            java.lang.String r2 = r3.d
        L1b:
            boolean r1 = kotlin.jvm.internal.Intrinsics.b(r1, r2)
            if (r1 != 0) goto L3f
        L21:
            com.facebook.login.v r0 = new com.facebook.login.v
            androidx.fragment.app.I r1 = r4.f()
            if (r1 == 0) goto L2a
            goto L2e
        L2a:
            android.content.Context r1 = com.facebook.o.a()
        L2e:
            com.facebook.login.LoginClient$Request r2 = r4.g
            if (r2 == 0) goto L36
            java.lang.String r2 = r2.d
            if (r2 != 0) goto L3a
        L36:
            java.lang.String r2 = com.facebook.o.b()
        L3a:
            r0.<init>(r1, r2)
            r4.j = r0
        L3f:
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.facebook.login.LoginClient.h():com.facebook.login.v");
    }

    public final void i(String str, String str2, String str3, String str4, HashMap map) {
        Request request = this.g;
        if (request == null) {
            h().a("fb_mobile_login_method_complete", str);
            return;
        }
        v vVarH = h();
        String str5 = request.e;
        String str6 = request.m ? "foa_mobile_login_method_complete" : "fb_mobile_login_method_complete";
        if (com.facebook.internal.instrument.crashshield.a.b(vVarH)) {
            return;
        }
        try {
            ScheduledExecutorService scheduledExecutorService = v.d;
            Bundle bundleB = A.b(str5);
            bundleB.putString("2_result", str2);
            if (str3 != null) {
                bundleB.putString("5_error_message", str3);
            }
            if (str4 != null) {
                bundleB.putString("4_error_code", str4);
            }
            if (map != null && !map.isEmpty()) {
                LinkedHashMap linkedHashMap = new LinkedHashMap();
                for (Map.Entry entry : map.entrySet()) {
                    if (((String) entry.getKey()) != null) {
                        linkedHashMap.put(entry.getKey(), entry.getValue());
                    }
                }
                bundleB.putString("6_extras", new JSONObject(linkedHashMap).toString());
            }
            bundleB.putString("3_method", str);
            vVarH.b.b(bundleB, str6);
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(vVarH, th);
        }
    }

    public final void j(int i, int i2, Intent intent) {
        this.k++;
        if (this.g != null) {
            if (intent != null) {
                int i3 = CustomTabMainActivity.c;
                if (intent.getBooleanExtra("CustomTabMainActivity.no_activity_exception", false)) {
                    l();
                    return;
                }
            }
            LoginMethodHandler loginMethodHandlerG = g();
            if (loginMethodHandlerG != null) {
                if ((loginMethodHandlerG instanceof KatanaProxyLoginMethodHandler) && intent == null && this.k < this.l) {
                    return;
                }
                loginMethodHandlerG.i(i, i2, intent);
            }
        }
    }

    public final void l() {
        LoginClient loginClient;
        LoginMethodHandler loginMethodHandlerG = g();
        if (loginMethodHandlerG != null) {
            loginClient = this;
            loginClient.i(loginMethodHandlerG.f(), "skipped", null, null, loginMethodHandlerG.a);
        } else {
            loginClient = this;
        }
        LoginMethodHandler[] loginMethodHandlerArr = loginClient.a;
        while (loginMethodHandlerArr != null) {
            int i = loginClient.b;
            if (i >= loginMethodHandlerArr.length - 1) {
                break;
            }
            loginClient.b = i + 1;
            LoginMethodHandler loginMethodHandlerG2 = g();
            if (loginMethodHandlerG2 != null) {
                if (!(loginMethodHandlerG2 instanceof WebViewLoginMethodHandler) || b()) {
                    Request request = loginClient.g;
                    if (request == null) {
                        continue;
                    } else {
                        int iM = loginMethodHandlerG2.m(request);
                        loginClient.k = 0;
                        if (iM > 0) {
                            v vVarH = h();
                            String str = request.e;
                            String strF = loginMethodHandlerG2.f();
                            String str2 = request.m ? "foa_mobile_login_method_start" : "fb_mobile_login_method_start";
                            if (!com.facebook.internal.instrument.crashshield.a.b(vVarH)) {
                                try {
                                    ScheduledExecutorService scheduledExecutorService = v.d;
                                    Bundle bundleB = A.b(str);
                                    bundleB.putString("3_method", strF);
                                    vVarH.b.b(bundleB, str2);
                                } catch (Throwable th) {
                                    com.facebook.internal.instrument.crashshield.a.a(vVarH, th);
                                }
                            }
                            loginClient.l = iM;
                        } else {
                            v vVarH2 = h();
                            String str3 = request.e;
                            String strF2 = loginMethodHandlerG2.f();
                            String str4 = request.m ? "foa_mobile_login_method_not_tried" : "fb_mobile_login_method_not_tried";
                            if (!com.facebook.internal.instrument.crashshield.a.b(vVarH2)) {
                                try {
                                    ScheduledExecutorService scheduledExecutorService2 = v.d;
                                    Bundle bundleB2 = A.b(str3);
                                    bundleB2.putString("3_method", strF2);
                                    vVarH2.b.b(bundleB2, str4);
                                } catch (Throwable th2) {
                                    com.facebook.internal.instrument.crashshield.a.a(vVarH2, th2);
                                }
                            }
                            a("not_tried", loginMethodHandlerG2.f(), true);
                        }
                        if (iM > 0) {
                            return;
                        }
                    }
                } else {
                    a("no_internet_permission", "1", false);
                }
            }
        }
        Request request2 = loginClient.g;
        if (request2 != null) {
            ArrayList arrayList = new ArrayList();
            arrayList.add("Login attempt failed.");
            c(new Result(request2, q.ERROR, null, TextUtils.join(": ", arrayList), null));
        }
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel dest, int i) {
        Intrinsics.checkNotNullParameter(dest, "dest");
        dest.writeParcelableArray(this.a, i);
        dest.writeInt(this.b);
        dest.writeParcelable(this.g, i);
        J.P(dest, this.h);
        J.P(dest, this.i);
    }

    @Metadata
    public static final class Request implements Parcelable {

        @NotNull
        public static final Parcelable.Creator<Request> CREATOR = new p();
        public final o a;
        public Set b;
        public final EnumC1567d c;
        public final String d;
        public final String e;
        public boolean f;
        public final String g;
        public final String h;
        public final String i;
        public String j;
        public boolean k;
        public final D l;
        public boolean m;
        public boolean n;
        public final String o;
        public final String p;
        public final String q;
        public final EnumC1564a r;

        public Request(Set set, String applicationId, String authId, String str, String str2, String str3, EnumC1564a enumC1564a) {
            D d = D.FACEBOOK;
            o loginBehavior = o.NATIVE_WITH_FALLBACK;
            EnumC1567d defaultAudience = EnumC1567d.FRIENDS;
            Intrinsics.checkNotNullParameter(loginBehavior, "loginBehavior");
            Intrinsics.checkNotNullParameter(defaultAudience, "defaultAudience");
            Intrinsics.checkNotNullParameter("rerequest", "authType");
            Intrinsics.checkNotNullParameter(applicationId, "applicationId");
            Intrinsics.checkNotNullParameter(authId, "authId");
            this.a = loginBehavior;
            this.b = set == null ? new HashSet() : set;
            this.c = defaultAudience;
            this.h = "rerequest";
            this.d = applicationId;
            this.e = authId;
            this.l = d;
            if (str == null || str.length() == 0) {
                this.o = androidx.compose.ui.node.B.f("randomUUID().toString()");
            } else {
                this.o = str;
            }
            this.p = str2;
            this.q = str3;
            this.r = enumC1564a;
        }

        @Override // android.os.Parcelable
        public final int describeContents() {
            return 0;
        }

        @Override // android.os.Parcelable
        public final void writeToParcel(Parcel dest, int i) {
            Intrinsics.checkNotNullParameter(dest, "dest");
            dest.writeString(this.a.name());
            dest.writeStringList(new ArrayList(this.b));
            dest.writeString(this.c.name());
            dest.writeString(this.d);
            dest.writeString(this.e);
            dest.writeByte(this.f ? (byte) 1 : (byte) 0);
            dest.writeString(this.g);
            dest.writeString(this.h);
            dest.writeString(this.i);
            dest.writeString(this.j);
            dest.writeByte(this.k ? (byte) 1 : (byte) 0);
            dest.writeString(this.l.name());
            dest.writeByte(this.m ? (byte) 1 : (byte) 0);
            dest.writeByte(this.n ? (byte) 1 : (byte) 0);
            dest.writeString(this.o);
            dest.writeString(this.p);
            dest.writeString(this.q);
            EnumC1564a enumC1564a = this.r;
            dest.writeString(enumC1564a != null ? enumC1564a.name() : null);
        }

        public Request(Parcel parcel) {
            EnumC1567d enumC1567dValueOf;
            D dValueOf;
            String string = parcel.readString();
            AbstractC1554i.j(string, "loginBehavior");
            this.a = o.valueOf(string);
            ArrayList arrayList = new ArrayList();
            parcel.readStringList(arrayList);
            this.b = new HashSet(arrayList);
            String string2 = parcel.readString();
            if (string2 != null) {
                enumC1567dValueOf = EnumC1567d.valueOf(string2);
            } else {
                enumC1567dValueOf = EnumC1567d.NONE;
            }
            this.c = enumC1567dValueOf;
            String string3 = parcel.readString();
            AbstractC1554i.j(string3, "applicationId");
            this.d = string3;
            String string4 = parcel.readString();
            AbstractC1554i.j(string4, "authId");
            this.e = string4;
            this.f = parcel.readByte() != 0;
            this.g = parcel.readString();
            String string5 = parcel.readString();
            AbstractC1554i.j(string5, "authType");
            this.h = string5;
            this.i = parcel.readString();
            this.j = parcel.readString();
            this.k = parcel.readByte() != 0;
            String string6 = parcel.readString();
            if (string6 != null) {
                dValueOf = D.valueOf(string6);
            } else {
                dValueOf = D.FACEBOOK;
            }
            this.l = dValueOf;
            this.m = parcel.readByte() != 0;
            this.n = parcel.readByte() != 0;
            String string7 = parcel.readString();
            AbstractC1554i.j(string7, "nonce");
            this.o = string7;
            this.p = parcel.readString();
            this.q = parcel.readString();
            String string8 = parcel.readString();
            this.r = string8 != null ? EnumC1564a.valueOf(string8) : null;
        }
    }
}

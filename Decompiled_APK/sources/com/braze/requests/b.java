package com.braze.requests;

import com.braze.AbstractC1484j;
import com.braze.Braze;
import com.braze.events.BrazeSdkAuthenticationErrorEvent;
import com.braze.managers.C;
import com.braze.storage.e0;
import com.braze.support.BrazeLogger;
import com.braze.support.JsonUtils;
import java.util.HashMap;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public abstract class b extends s implements n {
    public String b;
    public final e0 c;
    public Long d;
    public String e;
    public String f;
    public String g;
    public com.braze.models.outgoing.h h;
    public String i;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(com.braze.requests.util.c requestTarget, String str, e0 serverConfigStorageProvider) {
        super(requestTarget);
        Intrinsics.checkNotNullParameter(requestTarget, "requestTarget");
        Intrinsics.checkNotNullParameter(serverConfigStorageProvider, "serverConfigStorageProvider");
        this.b = str;
        this.c = serverConfigStorageProvider;
    }

    public static final String a(String str) {
        return AbstractC1484j.a("Error occurred while executing Braze request: ", str);
    }

    public static final String c(b bVar) {
        return bVar + " for " + bVar.c() + " executed successfully.";
    }

    public static final String d() {
        return "Experienced JSONException while retrieving parameters. Returning null.";
    }

    public static final String f() {
        return "******************************************************************";
    }

    public static final String g() {
        return "******************************************************************";
    }

    public static final String h() {
        return "**                        !! WARNING !!                         **";
    }

    public static final String i() {
        return "**  The current API key/endpoint combination is invalid. This   **";
    }

    public static final String j() {
        return "** is potentially an integration error. Please ensure that your **";
    }

    public static final String k() {
        return "**     API key AND custom endpoint information are correct.     **";
    }

    public JSONObject b() throws JSONException {
        JSONObject jSONObject = new JSONObject();
        try {
            com.braze.models.outgoing.h hVar = this.h;
            if (hVar != null && !hVar.isEmpty()) {
                jSONObject.put("device", hVar.forJsonPut());
            }
            String str = this.e;
            if (str != null) {
                jSONObject.put("device_id", str);
            }
            Long l = this.d;
            if (l != null) {
                jSONObject.put("time", l);
            }
            String str2 = this.f;
            if (str2 != null) {
                jSONObject.put("api_key", str2);
            }
            String str3 = this.g;
            if (str3 != null) {
                jSONObject.put("sdk_version", str3);
            }
            return jSONObject;
        } catch (JSONException e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) e, false, (Function0) new com.braze.models.outgoing.a(24), 4, (Object) null);
            return null;
        }
    }

    public final com.braze.requests.util.c e() {
        return new com.braze.requests.util.c(Braze.Companion.getApiEndpoint(this.a.b));
    }

    public String toString() {
        return hashCode() + " - " + JsonUtils.getPrettyPrintedString(b()) + "\nto target: " + e();
    }

    @Override // com.braze.requests.o
    public void a(com.braze.events.e internalPublisher, com.braze.events.e externalPublisher, com.braze.models.response.g apiResponse) {
        Intrinsics.checkNotNullParameter(internalPublisher, "internalPublisher");
        Intrinsics.checkNotNullParameter(externalPublisher, "externalPublisher");
        Intrinsics.checkNotNullParameter(apiResponse, "apiResponse");
        com.braze.models.response.i iVar = apiResponse.e;
        if (iVar != null) {
            ((com.braze.events.d) externalPublisher).b(new BrazeSdkAuthenticationErrorEvent(new com.braze.models.response.h(iVar.a, iVar.b, iVar.c, null)), BrazeSdkAuthenticationErrorEvent.class);
        }
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, this, (BrazeLogger.Priority) null, (Throwable) null, c() == m.n, new k(this, 0), 3, (Object) null);
    }

    @Override // com.braze.requests.o
    public void a(com.braze.events.e internalPublisher, com.braze.events.e externalPublisher, com.braze.models.response.d responseError) {
        Intrinsics.checkNotNullParameter(internalPublisher, "internalPublisher");
        Intrinsics.checkNotNullParameter(externalPublisher, "externalPublisher");
        Intrinsics.checkNotNullParameter(responseError, "responseError");
        String strA = responseError.a();
        BrazeLogger brazeLogger = BrazeLogger.INSTANCE;
        BrazeLogger.Priority priority = BrazeLogger.Priority.W;
        BrazeLogger.brazelog$default(brazeLogger, (Object) this, priority, (Throwable) null, false, (Function0) new C(strA, 25), 6, (Object) null);
        if (responseError instanceof com.braze.models.response.e) {
            ((com.braze.events.d) internalPublisher).b(responseError, com.braze.models.response.e.class);
            BrazeLogger.brazelog$default(brazeLogger, (Object) this, priority, (Throwable) null, false, (Function0) new com.braze.models.outgoing.a(26), 6, (Object) null);
            BrazeLogger.brazelog$default(brazeLogger, (Object) this, priority, (Throwable) null, false, (Function0) new com.braze.models.outgoing.a(27), 6, (Object) null);
            BrazeLogger.brazelog$default(brazeLogger, (Object) this, priority, (Throwable) null, false, (Function0) new com.braze.models.outgoing.a(28), 6, (Object) null);
            BrazeLogger.brazelog$default(brazeLogger, (Object) this, priority, (Throwable) null, false, (Function0) new com.braze.models.outgoing.a(29), 6, (Object) null);
            BrazeLogger.brazelog$default(brazeLogger, (Object) this, priority, (Throwable) null, false, (Function0) new y(0), 6, (Object) null);
            BrazeLogger.brazelog$default(brazeLogger, (Object) this, priority, (Throwable) null, false, (Function0) new k(this, 1), 6, (Object) null);
            BrazeLogger.brazelog$default(brazeLogger, (Object) this, priority, (Throwable) null, false, (Function0) new k(this, 2), 6, (Object) null);
            BrazeLogger.brazelog$default(brazeLogger, (Object) this, priority, (Throwable) null, false, (Function0) new com.braze.models.outgoing.a(25), 6, (Object) null);
        }
        if (responseError instanceof com.braze.models.response.h) {
            ((com.braze.events.d) externalPublisher).b(new BrazeSdkAuthenticationErrorEvent((com.braze.models.response.h) responseError), BrazeSdkAuthenticationErrorEvent.class);
        }
    }

    public static final String b(b bVar) {
        return ">> API key    : " + bVar.f;
    }

    public static final String a(b bVar) {
        return ">> Request Uri: " + bVar.e();
    }

    @Override // com.braze.requests.o
    public void a(com.braze.events.d internalPublisher) {
        Intrinsics.checkNotNullParameter(internalPublisher, "internalPublisher");
        internalPublisher.b(new com.braze.events.internal.r(this), com.braze.events.internal.r.class);
    }

    @Override // com.braze.requests.o
    public void a(com.braze.events.e internalPublisher) {
        Intrinsics.checkNotNullParameter(internalPublisher, "internalPublisher");
        ((com.braze.events.d) internalPublisher).b(new com.braze.events.internal.q(this), com.braze.events.internal.q.class);
    }

    public void a(HashMap existingHeaders) {
        Intrinsics.checkNotNullParameter(existingHeaders, "existingHeaders");
        existingHeaders.put("X-Braze-Api-Key", this.f);
        String str = this.i;
        if (str == null || str.length() == 0) {
            return;
        }
        existingHeaders.put("X-Braze-Auth-Signature", this.i);
    }
}

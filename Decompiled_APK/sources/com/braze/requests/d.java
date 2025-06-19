package com.braze.requests;

import androidx.navigation.compose.C1277j;
import com.braze.AbstractC1484j;
import com.braze.events.BrazeNetworkFailureEvent;
import com.braze.events.ContentCardsUpdatedEvent;
import com.braze.events.FeedUpdatedEvent;
import com.braze.events.NoMatchingTriggerEvent;
import com.braze.events.internal.h0;
import com.braze.managers.C;
import com.braze.managers.C1500m;
import com.braze.managers.o0;
import com.braze.models.inappmessage.IInAppMessage;
import com.braze.models.inappmessage.InAppMessageBase;
import com.braze.storage.e0;
import com.braze.support.BrazeLogger;
import com.braze.support.DateTimeUtils;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class d {
    public final com.braze.requests.framework.h a;
    public final com.braze.communication.e b;
    public final com.braze.events.e c;
    public final com.braze.events.e d;
    public final com.braze.storage.x e;
    public final C1500m f;
    public final e0 g;
    public final com.braze.storage.p h;
    public final com.braze.requests.util.a i;
    public final com.braze.requests.framework.c j;
    public final HashMap k;
    public final n l;

    public d(com.braze.requests.framework.h requestInfo, com.braze.communication.e httpConnector, com.braze.events.e internalPublisher, com.braze.events.e externalPublisher, com.braze.storage.x feedStorageProvider, C1500m brazeManager, e0 serverConfigStorage, com.braze.storage.p contentCardsStorage, com.braze.requests.util.a endpointMetadataProvider, com.braze.requests.framework.c requestDispatchCallback) {
        Intrinsics.checkNotNullParameter(requestInfo, "requestInfo");
        Intrinsics.checkNotNullParameter(httpConnector, "httpConnector");
        Intrinsics.checkNotNullParameter(internalPublisher, "internalPublisher");
        Intrinsics.checkNotNullParameter(externalPublisher, "externalPublisher");
        Intrinsics.checkNotNullParameter(feedStorageProvider, "feedStorageProvider");
        Intrinsics.checkNotNullParameter(brazeManager, "brazeManager");
        Intrinsics.checkNotNullParameter(serverConfigStorage, "serverConfigStorage");
        Intrinsics.checkNotNullParameter(contentCardsStorage, "contentCardsStorage");
        Intrinsics.checkNotNullParameter(endpointMetadataProvider, "endpointMetadataProvider");
        Intrinsics.checkNotNullParameter(requestDispatchCallback, "requestDispatchCallback");
        this.a = requestInfo;
        this.b = httpConnector;
        this.c = internalPublisher;
        this.d = externalPublisher;
        this.e = feedStorageProvider;
        this.f = brazeManager;
        this.g = serverConfigStorage;
        this.h = contentCardsStorage;
        this.i = endpointMetadataProvider;
        this.j = requestDispatchCallback;
        HashMap map = new HashMap();
        map.put("Accept-Encoding", "gzip, deflate");
        map.put("Content-Type", "application/json");
        this.k = map;
        n nVar = requestInfo.a;
        this.l = nVar;
        nVar.a(map);
    }

    public static final String a(String str) {
        return AbstractC1484j.a("Processing server response payload for user with id: ", str);
    }

    public static final String b() {
        return "Experienced network communication exception processing API response. Sending network error event.";
    }

    public static final String d() {
        return "Api response was null, failing task.";
    }

    public final void c() {
        com.braze.models.response.a aVarA = a();
        if (!(aVarA instanceof com.braze.models.response.g)) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new y(2), 6, (Object) null);
            com.braze.models.response.f fVar = new com.braze.models.response.f(this.l, aVarA.a);
            this.l.a(this.c, this.d, fVar);
            ((com.braze.events.d) this.c).b(new com.braze.events.internal.f(this.l), com.braze.events.internal.f.class);
            a(fVar);
            this.j.a(aVarA);
            return;
        }
        com.braze.models.response.g apiResponse = (com.braze.models.response.g) aVarA;
        Intrinsics.checkNotNullParameter(apiResponse, "apiResponse");
        com.braze.models.response.d dVar = apiResponse.d;
        if (dVar == null) {
            this.i.c(((b) this.l).e());
            this.l.a(this.c, this.d, apiResponse);
            this.j.a(apiResponse);
        } else {
            a(dVar);
            this.l.a(this.c, this.d, apiResponse.d);
            this.j.a((com.braze.models.response.a) apiResponse);
        }
        a(apiResponse);
        if (apiResponse.d instanceof com.braze.models.response.h) {
            ((com.braze.events.d) this.c).b(new com.braze.events.internal.f(this.l), com.braze.events.internal.f.class);
        } else {
            ((com.braze.events.d) this.c).b(new com.braze.events.internal.g(this.l), com.braze.events.internal.g.class);
        }
    }

    public static final String b(com.braze.models.response.d dVar) {
        return "Received server error from request: " + dVar.a();
    }

    public final com.braze.models.response.a a() throws IOException {
        ((b) this.l).d = Long.valueOf(DateTimeUtils.nowInSeconds());
        com.braze.requests.util.c cVarE = ((b) this.l).e();
        JSONObject jSONObjectB = this.l.b();
        if (jSONObjectB == null) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new com.braze.communication.h(cVarE, 1), 6, (Object) null);
            return new com.braze.models.response.n(this.l, new com.braze.communication.d(-1, (Map) null, 6));
        }
        this.k.put("X-Braze-Last-Req-Ms-Ago", String.valueOf(this.i.a(cVarE)));
        this.k.put("X-Braze-Req-Attempt", String.valueOf(this.i.b(cVarE)));
        this.k.put("X-Braze-Req-Tokens-Remaining", String.valueOf(this.a.e));
        Integer num = this.a.f;
        if (num != null) {
            this.k.put("X-Braze-Ept-Req-Tokens-Remaining", String.valueOf(num.intValue()));
        }
        int i = com.braze.communication.c.a;
        com.braze.communication.d dVarA = this.b.a(cVarE, this.k, jSONObjectB);
        if (dVarA.c != null) {
            return new com.braze.models.response.g(this.l, dVarA, this.f);
        }
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) null, false, (Function0) new y(1), 6, (Object) null);
        ((com.braze.events.d) this.d).b(new BrazeNetworkFailureEvent(this.l, dVarA), BrazeNetworkFailureEvent.class);
        return new com.braze.models.response.n(this.l, dVarA);
    }

    public final void b(ArrayList arrayList) {
        if (arrayList != null) {
            c.a(arrayList, new z(this, arrayList, 0));
        }
    }

    public static final Unit b(d dVar, List list) {
        ((com.braze.events.d) dVar.c).b(new h0(list), h0.class);
        return Unit.a;
    }

    public static final String a(com.braze.requests.util.c cVar) {
        return "Could not parse request parameters for POST request to " + cVar + ", cancelling request.";
    }

    public final void a(com.braze.models.response.g apiResponse) {
        Intrinsics.checkNotNullParameter(apiResponse, "apiResponse");
        String str = this.f.b;
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new C(str, 26), 6, (Object) null);
        a(apiResponse.m, str);
        a(apiResponse.f, str);
        a(apiResponse.i);
        b(apiResponse.h);
        a(apiResponse.j);
        a(apiResponse.k);
        a(apiResponse.g, str);
        String str2 = apiResponse.l;
        if (str2 != null) {
            ((com.braze.events.d) this.c).b(new com.braze.events.internal.h(str2), com.braze.events.internal.h.class);
        }
        a(apiResponse.o);
        o0 o0Var = apiResponse.p;
        if (o0Var != null) {
            ((com.braze.events.d) this.c).b(new com.braze.events.internal.t(o0Var), com.braze.events.internal.t.class);
        }
    }

    public final void a(com.braze.models.response.d responseError) {
        Intrinsics.checkNotNullParameter(responseError, "responseError");
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new A(responseError, 0), 6, (Object) null);
        ((com.braze.events.d) this.c).b(new com.braze.events.internal.x(responseError), com.braze.events.internal.x.class);
        n nVar = this.l;
        if (nVar instanceof x) {
            com.braze.events.e eVar = this.d;
            String strA = ((x) nVar).k.a();
            Intrinsics.checkNotNullExpressionValue(strA, "getTriggerEventType(...)");
            ((com.braze.events.d) eVar).b(new NoMatchingTriggerEvent(strA), NoMatchingTriggerEvent.class);
        }
    }

    public final void a(JSONArray jSONArray, String str) {
        if (jSONArray != null) {
            c.a(jSONArray, new androidx.work.impl.utils.q(this, jSONArray, str, 3));
        }
    }

    public static final Unit a(d dVar, JSONArray jSONArray, String str) throws JSONException {
        FeedUpdatedEvent feedUpdatedEventA = dVar.e.a(jSONArray, str);
        if (feedUpdatedEventA != null) {
            ((com.braze.events.d) dVar.d).b(feedUpdatedEventA, FeedUpdatedEvent.class);
        }
        return Unit.a;
    }

    public final void a(com.braze.models.response.c cVar, String str) {
        if (cVar != null) {
            c.a(cVar, new androidx.work.impl.utils.q(this, cVar, str, 4));
        }
    }

    public static final Unit a(d dVar, com.braze.models.response.c cVar, String str) {
        ContentCardsUpdatedEvent contentCardsUpdatedEventA = dVar.h.a(cVar, str);
        if (contentCardsUpdatedEventA != null) {
            ((com.braze.events.d) dVar.d).b(contentCardsUpdatedEventA, ContentCardsUpdatedEvent.class);
        }
        return Unit.a;
    }

    public final void a(com.braze.models.response.m mVar) {
        if (mVar != null) {
            c.a(mVar, new C1277j(17, this, mVar));
        }
    }

    public static final Unit a(d dVar, com.braze.models.response.m serverConfig) throws JSONException {
        dVar.g.a(serverConfig);
        ((com.braze.events.d) dVar.c).b(new com.braze.events.internal.w(serverConfig), com.braze.events.internal.w.class);
        Intrinsics.checkNotNullParameter(serverConfig, "serverConfig");
        o0 o0Var = new o0(serverConfig.y, serverConfig.A, serverConfig.z, serverConfig.B, serverConfig.C, serverConfig.D);
        ((com.braze.events.d) dVar.c).b(new com.braze.events.internal.t(o0Var), com.braze.events.internal.t.class);
        return Unit.a;
    }

    public final void a(ArrayList arrayList) {
        if (arrayList != null) {
            c.a(arrayList, new z(this, arrayList, 1));
        }
    }

    public static final Unit a(d dVar, List list) {
        ((com.braze.events.d) dVar.c).b(new com.braze.events.internal.l(list), com.braze.events.internal.l.class);
        return Unit.a;
    }

    public final void a(JSONArray jSONArray) {
        if (jSONArray != null) {
            c.a(jSONArray, new C1277j(16, this, jSONArray));
        }
    }

    public static final Unit a(d dVar, JSONArray jSONArray) {
        ((com.braze.events.d) dVar.c).b(new com.braze.events.internal.i(jSONArray), com.braze.events.internal.i.class);
        return Unit.a;
    }

    public final void a(JSONObject jSONObject) {
        if (jSONObject != null) {
            c.a(jSONObject, new C1277j(15, this, jSONObject));
        }
    }

    public static final Unit a(d dVar, JSONObject jSONObject) {
        ((com.braze.events.d) dVar.c).b(new com.braze.events.internal.a(jSONObject), com.braze.events.internal.a.class);
        return Unit.a;
    }

    public final void a(InAppMessageBase inAppMessageBase, String str) {
        if (inAppMessageBase != null) {
            c.a(inAppMessageBase, new androidx.work.impl.utils.q(this, inAppMessageBase, str, 5));
        }
    }

    public static final Unit a(d dVar, IInAppMessage iInAppMessage, String str) {
        n nVar = dVar.l;
        if (nVar instanceof x) {
            iInAppMessage.setExpirationTimestamp(((x) nVar).o);
            com.braze.events.e eVar = dVar.c;
            x xVar = (x) dVar.l;
            ((com.braze.events.d) eVar).b(new com.braze.events.internal.m(xVar.k, xVar.p, iInAppMessage, str), com.braze.events.internal.m.class);
        }
        return Unit.a;
    }
}

package com.braze.communication;

import androidx.work.impl.utils.q;
import com.braze.AbstractC1477c;
import com.braze.Y;
import com.braze.support.BrazeLogger;
import com.braze.support.JsonUtils;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.l;
import kotlin.text.x;
import kotlin.u;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class e {
    public final b a;

    public e(b httpConnector) {
        Intrinsics.checkNotNullParameter(httpConnector, "httpConnector");
        this.a = httpConnector;
    }

    public static final String b() {
        return "Exception while logging result: ";
    }

    public final d a(com.braze.requests.util.c requestTarget, HashMap requestHeaders, JSONObject payload) throws IOException {
        Intrinsics.checkNotNullParameter(requestTarget, "requestTarget");
        Intrinsics.checkNotNullParameter(requestHeaders, "requestHeaders");
        Intrinsics.checkNotNullParameter(payload, "payload");
        u uVarB = l.b(new q(requestTarget, requestHeaders, payload, 1));
        a(requestTarget, requestHeaders, uVarB, payload);
        long jCurrentTimeMillis = System.currentTimeMillis();
        d dVarA = this.a.a(requestTarget, requestHeaders, payload);
        a(uVarB, requestTarget, dVarA.b, dVarA.c, System.currentTimeMillis() - jCurrentTimeMillis);
        return dVarA;
    }

    public static final String a(com.braze.requests.util.c cVar, Map map, JSONObject jSONObject) {
        Object[] requestArgs = {cVar, map, jSONObject};
        String str = com.braze.support.l.a;
        Intrinsics.checkNotNullParameter(requestArgs, "requestArgs");
        long jHashCode = 1;
        for (int i = 0; i < 3; i++) {
            jHashCode *= requestArgs[i].hashCode();
        }
        String hexString = Long.toHexString(jHashCode);
        Intrinsics.checkNotNullExpressionValue(hexString, "toHexString(...)");
        return hexString;
    }

    public final void a(com.braze.requests.util.c cVar, HashMap map, kotlin.k kVar, JSONObject jSONObject) {
        try {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, this, (BrazeLogger.Priority) null, (Throwable) null, cVar.d, new i(kVar, cVar, this, map, jSONObject, 0), 3, (Object) null);
        } catch (Exception e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new Y(9), 4, (Object) null);
        }
    }

    public static final String a(kotlin.k kVar, com.braze.requests.util.c cVar, e eVar, Map map, JSONObject jSONObject) {
        String str;
        StringBuilder sb = new StringBuilder("\n                |Making request with id => \"");
        sb.append((String) kVar.getValue());
        sb.append("\"\n                |to url: ");
        sb.append(cVar);
        sb.append("\n                \n                |with headers:\n                ");
        eVar.getClass();
        sb.append(a(map));
        sb.append("\n                |\n                |");
        if (jSONObject == null) {
            str = "";
        } else {
            str = "and JSON :\n" + JsonUtils.getPrettyPrintedString(jSONObject);
        }
        return x.d(AbstractC1477c.a(sb, str, "\n                "));
    }

    public static final String a() {
        return "Exception while logging request: ";
    }

    public final void a(final kotlin.k kVar, final com.braze.requests.util.c cVar, final Map map, final JSONObject jSONObject, final long j) {
        try {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, new Function0() { // from class: com.braze.communication.j
                @Override // kotlin.jvm.functions.Function0
                public final Object invoke() {
                    return e.a(kVar, cVar, j, this, map, jSONObject);
                }
            }, 7, (Object) null);
        } catch (Exception e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new Y(10), 4, (Object) null);
        }
    }

    public static final String a(kotlin.k kVar, com.braze.requests.util.c cVar, long j, e eVar, Map map, JSONObject jSONObject) {
        StringBuilder sb = new StringBuilder("\n                |Made request with id => \"");
        sb.append((String) kVar.getValue());
        sb.append("\"\n                |to url: ");
        sb.append(cVar);
        sb.append("\n                |took: ");
        sb.append(j);
        sb.append("ms\n                \n                |with response headers:\n                ");
        eVar.getClass();
        sb.append(a(map));
        sb.append("\n                |\n                |and response JSON:\n                |");
        sb.append(JsonUtils.getPrettyPrintedString(jSONObject));
        sb.append("\n                ");
        return x.d(sb.toString());
    }

    public static String a(Map map) {
        ArrayList arrayList = new ArrayList(map.size());
        for (Map.Entry entry : map.entrySet()) {
            arrayList.add("|\"" + ((String) entry.getKey()) + "\" => \"" + ((String) entry.getValue()) + '\"');
        }
        return CollectionsKt.S(arrayList, "\n", null, null, null, 62);
    }
}

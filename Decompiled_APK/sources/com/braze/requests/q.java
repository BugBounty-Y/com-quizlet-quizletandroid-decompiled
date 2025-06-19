package com.braze.requests;

import com.braze.storage.e0;
import com.braze.support.BrazeLogger;
import java.util.ArrayList;
import java.util.Iterator;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class q extends b {
    public final ArrayList j;
    public final boolean k;
    public final m l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public q(e0 serverConfigStorageProvider, String urlBase, String str, ArrayList pushDeliveryEvents) {
        super(new com.braze.requests.util.c(android.support.v4.media.session.a.k(urlBase, "push/delivery_events"), false), str, serverConfigStorageProvider);
        Intrinsics.checkNotNullParameter(serverConfigStorageProvider, "serverConfigStorageProvider");
        Intrinsics.checkNotNullParameter(urlBase, "urlBase");
        Intrinsics.checkNotNullParameter(pushDeliveryEvents, "pushDeliveryEvents");
        this.j = pushDeliveryEvents;
        this.k = pushDeliveryEvents.isEmpty();
        this.l = m.h;
    }

    public static final String d() {
        return "Experienced JSONException while creating PushDeliverySendRequest. Returning null.";
    }

    @Override // com.braze.requests.n
    public final boolean a() {
        return this.k;
    }

    @Override // com.braze.requests.b, com.braze.requests.n
    public final JSONObject b() throws JSONException {
        JSONObject jSONObjectB = super.b();
        if (jSONObjectB == null) {
            return null;
        }
        try {
            JSONArray jSONArray = new JSONArray();
            Iterator it2 = this.j.iterator();
            while (it2.hasNext()) {
                com.braze.models.push.a aVar = (com.braze.models.push.a) it2.next();
                aVar.e.setValue(aVar, com.braze.models.outgoing.event.b.h[0], this.b);
                jSONArray.put(aVar.forJsonPut());
            }
            jSONObjectB.put("events", jSONArray);
            String str = this.b;
            if (str != null && !StringsKt.O(str)) {
                jSONObjectB.put("user_id", this.b);
            }
            return jSONObjectB;
        } catch (JSONException e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) e, false, (Function0) new y(19), 4, (Object) null);
            return null;
        }
    }

    @Override // com.braze.requests.n
    public final m c() {
        return this.l;
    }
}

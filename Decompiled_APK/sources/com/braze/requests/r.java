package com.braze.requests;

import com.braze.storage.e0;
import com.braze.support.BrazeLogger;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class r extends b {
    public final ArrayList j;
    public final long k;
    public final List l;
    public final m m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public r(e0 serverConfigStorageProvider, String urlBase, String str, ArrayList campaignIds, long j, List dedupeIds) {
        super(new com.braze.requests.util.c(android.support.v4.media.session.a.k(urlBase, "push/redeliver"), false), str, serverConfigStorageProvider);
        Intrinsics.checkNotNullParameter(serverConfigStorageProvider, "serverConfigStorageProvider");
        Intrinsics.checkNotNullParameter(urlBase, "urlBase");
        Intrinsics.checkNotNullParameter(campaignIds, "campaignIds");
        Intrinsics.checkNotNullParameter(dedupeIds, "dedupeIds");
        this.j = campaignIds;
        this.k = j;
        this.l = dedupeIds;
        this.m = m.k;
    }

    public static final String l() {
        return "Experienced JSONException while creating PushMaxSendRequest. Returning null.";
    }

    public static final String m() {
        return "PushMaxSendRequest executed successfully.";
    }

    @Override // com.braze.requests.n
    public final boolean a() {
        return false;
    }

    @Override // com.braze.requests.b, com.braze.requests.n
    public final JSONObject b() throws JSONException {
        JSONObject jSONObjectB = super.b();
        if (jSONObjectB == null) {
            return null;
        }
        try {
            String str = this.b;
            if (str != null && !StringsKt.O(str)) {
                jSONObjectB.put("user_id", this.b);
            }
            jSONObjectB.put("campaign_ids", new JSONArray((Collection) this.j));
            jSONObjectB.put("last_sync_at", this.k);
            if (!this.l.isEmpty()) {
                jSONObjectB.put("dedupe_ids", new JSONArray((Collection) this.l));
            }
            return jSONObjectB;
        } catch (JSONException e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) e, false, (Function0) new y(20), 4, (Object) null);
            return null;
        }
    }

    @Override // com.braze.requests.n
    public final m c() {
        return this.m;
    }

    @Override // com.braze.requests.b, com.braze.requests.o
    public final void a(com.braze.events.e internalPublisher, com.braze.events.e externalPublisher, com.braze.models.response.g apiResponse) {
        Intrinsics.checkNotNullParameter(internalPublisher, "internalPublisher");
        Intrinsics.checkNotNullParameter(externalPublisher, "externalPublisher");
        Intrinsics.checkNotNullParameter(apiResponse, "apiResponse");
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new y(21), 7, (Object) null);
        long j = apiResponse.n;
        if (j != -1) {
            ((com.braze.events.d) internalPublisher).b(new com.braze.events.internal.p(j), com.braze.events.internal.p.class);
        }
    }
}

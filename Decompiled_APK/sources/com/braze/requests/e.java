package com.braze.requests;

import com.braze.storage.e0;
import com.braze.support.BrazeLogger;
import java.util.HashMap;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class e extends b {
    public long j;
    public long k;
    public int l;
    public final m m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(e0 serverConfigStorageProvider, String urlBase, long j, long j2, String str, int i) {
        super(new com.braze.requests.util.c(android.support.v4.media.session.a.k(urlBase, "content_cards/sync"), false), str, serverConfigStorageProvider);
        Intrinsics.checkNotNullParameter(serverConfigStorageProvider, "serverConfigStorageProvider");
        Intrinsics.checkNotNullParameter(urlBase, "urlBase");
        this.j = j;
        this.k = j2;
        this.l = i;
        this.m = m.d;
    }

    public static final String l() {
        return "Experienced JSONException while creating Content Cards request. Returning null.";
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
            jSONObjectB.put("last_full_sync_at", this.k);
            jSONObjectB.put("last_card_updated_at", this.j);
            String str = this.b;
            if (str != null && !StringsKt.O(str)) {
                jSONObjectB.put("user_id", this.b);
                return jSONObjectB;
            }
            return jSONObjectB;
        } catch (JSONException e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) e, false, (Function0) new y(3), 4, (Object) null);
            return null;
        }
    }

    @Override // com.braze.requests.n
    public final m c() {
        return this.m;
    }

    @Override // com.braze.requests.b, com.braze.requests.n
    public final void a(HashMap existingHeaders) {
        Intrinsics.checkNotNullParameter(existingHeaders, "existingHeaders");
        super.a(existingHeaders);
        existingHeaders.put("X-Braze-DataRequest", "true");
        existingHeaders.put("X-Braze-ContentCardsRequest", "true");
        existingHeaders.put("BRAZE-SYNC-RETRY-COUNT", String.valueOf(this.l));
    }
}

package com.braze.requests;

import com.braze.enums.BrazeSdkMetadata;
import com.braze.enums.SdkFlavor;
import com.braze.events.internal.c0;
import com.braze.events.internal.d0;
import com.braze.storage.e0;
import com.braze.support.BrazeLogger;
import com.braze.support.JsonUtils;
import java.util.ArrayList;
import java.util.Collection;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Iterator;
import kotlin.collections.C;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class f extends b {
    public com.braze.models.outgoing.k j;
    public SdkFlavor k;
    public com.braze.models.outgoing.l l;
    public com.braze.models.b m;
    public EnumSet n;
    public String o;
    public String p;
    public final m q;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public f(e0 serverConfigStorageProvider, String urlBase, com.braze.models.outgoing.k outboundRespondWith) {
        super(new com.braze.requests.util.c(android.support.v4.media.session.a.k(urlBase, "data"), false), null, serverConfigStorageProvider);
        Intrinsics.checkNotNullParameter(serverConfigStorageProvider, "serverConfigStorageProvider");
        Intrinsics.checkNotNullParameter(urlBase, "urlBase");
        Intrinsics.checkNotNullParameter(outboundRespondWith, "outboundRespondWith");
        this.j = outboundRespondWith;
        this.q = m.f;
    }

    public static final String l() {
        return "Experienced JSONException while retrieving parameters. Returning empty object.";
    }

    public static final String m() {
        return "Trigger dispatch completed. Alerting subscribers.";
    }

    @Override // com.braze.requests.n
    public final boolean a() {
        ArrayList arrayList = new ArrayList();
        arrayList.add(this.h);
        arrayList.add(this.l);
        arrayList.add(this.m);
        arrayList.add(this.j);
        if (!arrayList.isEmpty()) {
            Iterator it2 = arrayList.iterator();
            while (it2.hasNext()) {
                com.braze.models.k kVar = (com.braze.models.k) it2.next();
                if (kVar != null && !kVar.isEmpty()) {
                    return false;
                }
            }
        }
        ArrayList arrayList2 = new ArrayList();
        arrayList2.add(this.h);
        Iterator it3 = arrayList2.iterator();
        while (it3.hasNext()) {
            com.braze.models.k kVar2 = (com.braze.models.k) it3.next();
            if (kVar2 != null && !kVar2.isEmpty()) {
                return false;
            }
        }
        return true;
    }

    @Override // com.braze.requests.b, com.braze.requests.n
    public final JSONObject b() throws JSONException {
        JSONObject jSONObjectB = super.b();
        if (jSONObjectB == null) {
            return null;
        }
        try {
            String str = this.o;
            if (str != null) {
                jSONObjectB.put("app_version", str);
            }
            String str2 = this.p;
            if (str2 != null && !StringsKt.O(str2)) {
                jSONObjectB.put("app_version_code", this.p);
            }
            com.braze.models.outgoing.l lVar = this.l;
            if (lVar != null && !lVar.isEmpty()) {
                JSONArray jsonArrayForJsonPut = lVar.b;
                Intrinsics.checkNotNullExpressionValue(jsonArrayForJsonPut, "jsonArrayForJsonPut");
                jSONObjectB.put("attributes", jsonArrayForJsonPut);
            }
            com.braze.models.b bVar = this.m;
            if (bVar != null && !bVar.b) {
                jSONObjectB.put("events", JsonUtils.constructJsonArray(bVar.a));
            }
            SdkFlavor sdkFlavor = this.k;
            if (sdkFlavor != null) {
                jSONObjectB.put("sdk_flavor", sdkFlavor.forJsonPut());
            }
            EnumSet set = this.n;
            if (set != null) {
                BrazeSdkMetadata.Companion.getClass();
                Intrinsics.checkNotNullParameter(set, "set");
                ArrayList arrayList = new ArrayList(C.q(set, 10));
                Iterator it2 = set.iterator();
                while (it2.hasNext()) {
                    arrayList.add(((BrazeSdkMetadata) it2.next()).jsonKey);
                }
                jSONObjectB.put("sdk_metadata", new JSONArray((Collection) CollectionsKt.m0(arrayList)));
            }
            jSONObjectB.put("respond_with", this.j.forJsonPut());
            return jSONObjectB;
        } catch (JSONException e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) e, false, (Function0) new y(4), 4, (Object) null);
            return null;
        }
    }

    @Override // com.braze.requests.n
    public final m c() {
        return this.q;
    }

    @Override // com.braze.requests.b, com.braze.requests.o
    public final void a(com.braze.events.d internalPublisher) {
        Intrinsics.checkNotNullParameter(internalPublisher, "internalPublisher");
        if (this.j.b()) {
            internalPublisher.b(new d0(this), d0.class);
        }
    }

    @Override // com.braze.requests.b, com.braze.requests.o
    public final void a(com.braze.events.e internalPublisher) {
        Intrinsics.checkNotNullParameter(internalPublisher, "internalPublisher");
        if (this.j.b()) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new y(5), 7, (Object) null);
            ((com.braze.events.d) internalPublisher).b(new c0(this), c0.class);
        }
    }

    @Override // com.braze.requests.b, com.braze.requests.n
    public final void a(HashMap existingHeaders) {
        boolean z;
        Intrinsics.checkNotNullParameter(existingHeaders, "existingHeaders");
        super.a(existingHeaders);
        if (this.j.isEmpty()) {
            return;
        }
        boolean z2 = true;
        if (this.j.b != null) {
            existingHeaders.put("X-Braze-FeedRequest", "true");
            z = true;
        } else {
            z = false;
        }
        if (this.j.b()) {
            existingHeaders.put("X-Braze-TriggersRequest", "true");
        } else {
            z2 = z;
        }
        if (z2) {
            existingHeaders.put("X-Braze-DataRequest", "true");
        }
    }
}

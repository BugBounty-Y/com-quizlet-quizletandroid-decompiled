package com.braze.triggers.actions;

import android.content.Context;
import com.braze.enums.inappmessage.MessageType;
import com.braze.events.internal.m;
import com.braze.managers.C1500m;
import com.braze.models.inappmessage.InAppMessageBase;
import com.braze.support.BrazeLogger;
import com.braze.support.JsonUtils;
import com.braze.support.n;
import com.braze.support.v;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.collections.V;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class c extends h {
    public final InAppMessageBase g;
    public final JSONObject h;
    public final C1500m i;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(JSONObject json, C1500m brazeManager) throws JSONException {
        super(json);
        Intrinsics.checkNotNullParameter(json, "json");
        Intrinsics.checkNotNullParameter(brazeManager, "brazeManager");
        BrazeLogger brazeLogger = BrazeLogger.INSTANCE;
        BrazeLogger.brazelog$default(brazeLogger, (Object) this, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new com.braze.communication.dust.j(json, 19), 6, (Object) null);
        JSONObject jSONObject = json.getJSONObject("data");
        this.i = brazeManager;
        this.h = jSONObject;
        Intrinsics.d(jSONObject);
        InAppMessageBase inAppMessageBaseA = n.a(jSONObject, brazeManager);
        this.g = inAppMessageBaseA;
        if (inAppMessageBaseA != null) {
            return;
        }
        BrazeLogger.brazelog$default(brazeLogger, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new v(24), 6, (Object) null);
        throw new IllegalArgumentException("Failed to parse in-app message triggered action with JSON: " + JsonUtils.getPrettyPrintedString(json));
    }

    public static final String b() {
        return "In-app message has no remote assets for prefetch. Returning empty list.";
    }

    public static final String c() {
        return "Failed to parse in-app message triggered action.";
    }

    public static final String d(com.braze.triggers.events.b bVar) {
        return "Cannot perform triggered action for " + bVar + " due to deserialized in-app message being null";
    }

    @Override // com.braze.triggers.actions.a
    public final ArrayList a() {
        ArrayList arrayList = new ArrayList();
        InAppMessageBase inAppMessageBase = this.g;
        List<String> remoteAssetPathsForPrefetch = inAppMessageBase != null ? inAppMessageBase.getRemoteAssetPathsForPrefetch() : null;
        if (remoteAssetPathsForPrefetch == null || remoteAssetPathsForPrefetch.isEmpty()) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new v(26), 7, (Object) null);
            return arrayList;
        }
        InAppMessageBase inAppMessageBase2 = this.g;
        MessageType messageType = inAppMessageBase2 != null ? inAppMessageBase2.getMessageType() : null;
        int i = messageType == null ? -1 : b.a[messageType.ordinal()];
        if (i == 1) {
            arrayList.add(new com.braze.triggers.utils.a(com.braze.triggers.enums.b.a, remoteAssetPathsForPrefetch.get(0)));
            return arrayList;
        }
        if (i == 2 || i == 3 || i == 4) {
            arrayList.add(new com.braze.triggers.utils.a(com.braze.triggers.enums.b.b, remoteAssetPathsForPrefetch.get(0)));
            return arrayList;
        }
        if (i != 5) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new i(this, 1), 6, (Object) null);
            return arrayList;
        }
        Iterator<String> it2 = remoteAssetPathsForPrefetch.iterator();
        while (it2.hasNext()) {
            arrayList.add(new com.braze.triggers.utils.a(com.braze.triggers.enums.b.c, it2.next()));
        }
        return arrayList;
    }

    @Override // com.braze.triggers.actions.g, com.braze.models.IPutIntoJson
    public final Object forJsonPut() throws JSONException {
        try {
            JSONObject jSONObjectForJsonPut = super.forJsonPut();
            if (jSONObjectForJsonPut != null) {
                InAppMessageBase inAppMessageBase = this.g;
                jSONObjectForJsonPut.put("data", inAppMessageBase != null ? inAppMessageBase.forJsonPut() : null);
                jSONObjectForJsonPut.put(DBUserFields.Names.USER_UPGRADE_TYPE, "inapp");
                return jSONObjectForJsonPut;
            }
        } catch (JSONException unused) {
        }
        return null;
    }

    public static final String b(c cVar) {
        return android.support.v4.media.session.a.r(new StringBuilder("Attempting to publish in-app message after delay of "), cVar.b.d, " seconds.");
    }

    public static final String c(com.braze.triggers.events.b bVar) {
        return "Cannot perform triggered action for " + bVar + " due to in-app message json being null";
    }

    public static final String d() {
        return "Caught exception while performing triggered action.";
    }

    public static final String a(c cVar) {
        StringBuilder sb = new StringBuilder("Failed to return remote paths to assets for type: ");
        InAppMessageBase inAppMessageBase = cVar.g;
        sb.append(inAppMessageBase != null ? inAppMessageBase.getMessageType() : null);
        return sb.toString();
    }

    public static final String a(JSONObject jSONObject) {
        return "Attempting to parse in-app message triggered action with JSON: " + JsonUtils.getPrettyPrintedString(jSONObject);
    }

    @Override // com.braze.triggers.actions.a
    public final void a(Context context, com.braze.events.e internalEventPublisher, com.braze.triggers.events.b triggerEvent, long j) throws JSONException {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(internalEventPublisher, "internalEventPublisher");
        Intrinsics.checkNotNullParameter(triggerEvent, "triggerEvent");
        try {
            BrazeLogger brazeLogger = BrazeLogger.INSTANCE;
            BrazeLogger.brazelog$default(brazeLogger, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new i(this, 0), 7, (Object) null);
            JSONObject jSONObject = this.h;
            if (jSONObject == null) {
                BrazeLogger.brazelog$default(brazeLogger, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new j(triggerEvent, 0), 6, (Object) null);
                return;
            }
            InAppMessageBase inAppMessageBaseA = n.a(jSONObject, this.i);
            String strA = triggerEvent.a();
            int i = com.braze.triggers.events.h.g;
            if (Intrinsics.b(strA, "test")) {
                if (inAppMessageBaseA != null) {
                    inAppMessageBaseA.setTestSend(true);
                }
                this.h.put("is_test_send", true);
            }
            if (inAppMessageBaseA == null) {
                BrazeLogger.brazelog$default(brazeLogger, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new j(triggerEvent, 1), 6, (Object) null);
                return;
            }
            inAppMessageBaseA.setLocalPrefetchedAssetPaths(V.l(this.f));
            inAppMessageBaseA.setExpirationTimestamp(j);
            ((com.braze.events.d) internalEventPublisher).b(new m(triggerEvent, this, inAppMessageBaseA, this.i.b), m.class);
        } catch (Exception e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) e, false, (Function0) new v(25), 4, (Object) null);
        }
    }
}

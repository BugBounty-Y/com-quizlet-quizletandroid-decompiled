package com.braze.triggers.actions;

import android.content.Context;
import com.braze.managers.C1500m;
import com.braze.requests.framework.o;
import com.braze.requests.x;
import com.braze.support.BrazeLogger;
import com.braze.support.JsonUtils;
import com.braze.support.v;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;
import java.util.ArrayList;
import java.util.Iterator;
import kotlin.NoWhenBranchMatchedException;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.ranges.l;
import kotlin.sequences.q;
import kotlin.sequences.t;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class f extends h {
    public final C1500m g;
    public final String h;
    public final ArrayList i;
    public long j;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public f(JSONObject json, C1500m brazeManager) throws JSONException {
        super(json);
        Intrinsics.checkNotNullParameter(json, "json");
        Intrinsics.checkNotNullParameter(brazeManager, "brazeManager");
        this.i = new ArrayList();
        this.j = -1L;
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new com.braze.communication.dust.j(json, 20), 7, (Object) null);
        this.g = brazeManager;
        JSONObject jSONObject = json.getJSONObject("data");
        this.h = jSONObject.getString("trigger_id");
        JSONArray jSONArrayOptJSONArray = jSONObject.optJSONArray("prefetch_image_urls");
        if (jSONArrayOptJSONArray != null) {
            a(jSONArrayOptJSONArray, com.braze.triggers.enums.b.b);
        }
        JSONArray jSONArrayOptJSONArray2 = jSONObject.optJSONArray("prefetch_zip_urls");
        if (jSONArrayOptJSONArray2 != null) {
            a(jSONArrayOptJSONArray2, com.braze.triggers.enums.b.a);
        }
        JSONArray jSONArrayOptJSONArray3 = jSONObject.optJSONArray("prefetch_file_urls");
        if (jSONArrayOptJSONArray3 != null) {
            a(jSONArrayOptJSONArray3, com.braze.triggers.enums.b.c);
        }
    }

    public static final String b() {
        return "Could not convert TemplatedTriggeredAction to JSON";
    }

    @Override // com.braze.triggers.actions.a
    public final ArrayList a() {
        return new ArrayList(this.i);
    }

    @Override // com.braze.triggers.actions.g, com.braze.models.IPutIntoJson
    public final JSONObject forJsonPut() throws JSONException {
        try {
            JSONObject jSONObjectForJsonPut = super.forJsonPut();
            if (jSONObjectForJsonPut == null) {
                return null;
            }
            jSONObjectForJsonPut.put(DBUserFields.Names.USER_UPGRADE_TYPE, "templated_iam");
            JSONObject jSONObject = new JSONObject();
            jSONObject.put("trigger_id", this.h);
            JSONArray jSONArray = new JSONArray();
            JSONArray jSONArray2 = new JSONArray();
            JSONArray jSONArray3 = new JSONArray();
            Iterator it2 = this.i.iterator();
            while (it2.hasNext()) {
                com.braze.triggers.utils.a aVar = (com.braze.triggers.utils.a) it2.next();
                int iOrdinal = aVar.a.ordinal();
                if (iOrdinal == 0) {
                    jSONArray2.put(aVar.b);
                } else if (iOrdinal == 1) {
                    jSONArray.put(aVar.b);
                } else {
                    if (iOrdinal != 2) {
                        throw new NoWhenBranchMatchedException();
                    }
                    jSONArray3.put(aVar.b);
                }
            }
            jSONObject.put("prefetch_image_urls", jSONArray);
            jSONObject.put("prefetch_zip_urls", jSONArray2);
            jSONObject.put("prefetch_file_urls", jSONArray3);
            jSONObjectForJsonPut.put("data", jSONObject);
            return jSONObjectForJsonPut;
        } catch (JSONException e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new v(27), 4, (Object) null);
            return null;
        }
    }

    public static final String a(JSONObject jSONObject) {
        return "Parsing templated triggered action with JSON: " + JsonUtils.getPrettyPrintedString(jSONObject);
    }

    @Override // com.braze.triggers.actions.a
    public final void a(Context context, com.braze.events.e internalEventPublisher, com.braze.triggers.events.b triggerEvent, long j) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(internalEventPublisher, "internalEventPublisher");
        Intrinsics.checkNotNullParameter(triggerEvent, "triggerEvent");
        this.j = j;
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new o(this, 9), 7, (Object) null);
        C1500m c1500m = this.g;
        c1500m.getClass();
        Intrinsics.checkNotNullParameter(this, "templatedTriggeredAction");
        Intrinsics.checkNotNullParameter(triggerEvent, "triggerEvent");
        c1500m.a(new x(c1500m.f, c1500m.e.getBaseUrlForRequests(), this, triggerEvent, c1500m.b));
    }

    public static final String a(f fVar) {
        return android.support.v4.media.session.a.r(new StringBuilder("Posting templating request after delay of "), fVar.b.d, " seconds.");
    }

    public final void a(JSONArray jSONArray, com.braze.triggers.enums.b bVar) {
        t tVarH = q.h(q.e(CollectionsKt.D(l.h(0, jSONArray.length())), new d(jSONArray)), new e(jSONArray));
        Iterator it2 = tVarH.b.iterator();
        while (it2.hasNext()) {
            this.i.add(new com.braze.triggers.utils.a(bVar, (String) tVarH.c.invoke(it2.next())));
        }
    }
}

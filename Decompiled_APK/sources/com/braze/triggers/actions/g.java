package com.braze.triggers.actions;

import androidx.navigation.compose.C1277j;
import com.braze.support.BrazeLogger;
import com.braze.support.DateTimeUtils;
import java.util.ArrayList;
import java.util.Iterator;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public abstract class g implements a {
    public final String a;
    public final com.braze.triggers.config.c b;
    public final boolean c;
    public com.braze.triggers.utils.b d;
    public final ArrayList e;

    public g(JSONObject json) throws JSONException {
        Intrinsics.checkNotNullParameter(json, "json");
        ArrayList arrayList = new ArrayList();
        this.e = arrayList;
        this.a = json.getString("id");
        this.b = new com.braze.triggers.config.c(json);
        JSONArray jSONArray = json.getJSONArray("trigger_condition");
        if (jSONArray.length() > 0) {
            arrayList.addAll(com.braze.triggers.utils.c.a(jSONArray));
        }
        this.c = json.optBoolean("prefetch", true);
    }

    public static final String a(g gVar, com.braze.triggers.events.b bVar) {
        return "Triggered action " + gVar.a + " not eligible to be triggered by " + bVar.a() + " event. Current device time outside triggered action time window.";
    }

    public final boolean b(com.braze.triggers.events.b event) {
        Intrinsics.checkNotNullParameter(event, "event");
        if ((this.b.a != -1 && DateTimeUtils.nowInSeconds() <= this.b.a) || (this.b.b != -1 && DateTimeUtils.nowInSeconds() >= this.b.b)) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new C1277j(29, this, event), 7, (Object) null);
            return false;
        }
        Iterator it2 = this.e.iterator();
        int i = 0;
        while (true) {
            if (!it2.hasNext()) {
                i = -1;
                break;
            }
            if (((com.braze.triggers.conditions.d) it2.next()).a(event)) {
                break;
            }
            i++;
        }
        return i != -1;
    }

    @Override // com.braze.models.IPutIntoJson
    public JSONObject forJsonPut() throws JSONException {
        try {
            JSONObject jSONObjectForJsonPut = this.b.forJsonPut();
            if (jSONObjectForJsonPut == null) {
                return null;
            }
            jSONObjectForJsonPut.put("id", this.a);
            JSONArray jSONArray = new JSONArray();
            Iterator it2 = this.e.iterator();
            while (it2.hasNext()) {
                jSONArray.put(((com.braze.triggers.conditions.d) it2.next()).forJsonPut());
            }
            jSONObjectForJsonPut.put("trigger_condition", jSONArray);
            jSONObjectForJsonPut.put("prefetch", this.c);
            return jSONObjectForJsonPut;
        } catch (JSONException unused) {
            return null;
        }
    }
}

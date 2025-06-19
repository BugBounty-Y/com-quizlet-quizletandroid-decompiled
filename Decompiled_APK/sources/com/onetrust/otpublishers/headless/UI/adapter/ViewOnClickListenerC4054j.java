package com.onetrust.otpublishers.headless.UI.adapter;

import android.graphics.Color;
import android.view.View;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.recyclerview.widget.AbstractC1361d0;
import com.google.android.gms.measurement.internal.Z;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import java.util.HashMap;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* renamed from: com.onetrust.otpublishers.headless.UI.adapter.j, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class ViewOnClickListenerC4054j implements View.OnClickListener {
    public final /* synthetic */ int a = 0;
    public final /* synthetic */ String b;
    public final /* synthetic */ AbstractC1361d0 c;
    public final /* synthetic */ Object d;
    public final /* synthetic */ Object e;

    public /* synthetic */ ViewOnClickListenerC4054j(m mVar, JSONObject jSONObject, C4056l c4056l, String str) {
        this.c = mVar;
        this.d = jSONObject;
        this.e = c4056l;
        this.b = str;
    }

    @Override // android.view.View.OnClickListener
    public final void onClick(View view) throws JSONException {
        String str;
        switch (this.a) {
            case 0:
                JSONObject jSONObject = (JSONObject) this.d;
                String str2 = this.b;
                m mVar = (m) this.c;
                mVar.getClass();
                try {
                    boolean zHas = jSONObject.has("SubGroups");
                    C4056l c4056l = (C4056l) this.e;
                    if (zHas) {
                        JSONArray jSONArray = jSONObject.getJSONArray("SubGroups");
                        boolean zIsChecked = c4056l.d.isChecked();
                        for (int i = 0; i < jSONArray.length(); i++) {
                            JSONObject jSONObject2 = jSONArray.getJSONObject(i);
                            String string = jSONObject2.getString("CustomGroupId");
                            if (jSONObject2.optBoolean("HasConsentOptOut", false)) {
                                mVar.g(string, zIsChecked);
                                mVar.c.updatePurposeConsent(string, zIsChecked);
                            }
                        }
                    }
                    mVar.g(str2, c4056l.d.isChecked());
                    break;
                } catch (JSONException e) {
                    Z.p("error in setting subgroup consent parent ", e, "OneTrust", 6);
                    return;
                }
            default:
                o oVar = (o) this.c;
                n nVar = (n) this.d;
                boolean zIsChecked2 = nVar.b.isChecked();
                com.onetrust.otpublishers.headless.UI.UIProperty.g gVar = (com.onetrust.otpublishers.headless.UI.UIProperty.g) oVar.f;
                if (gVar != null && !com.onetrust.otpublishers.headless.Internal.a.j(gVar.h) && !com.onetrust.otpublishers.headless.Internal.a.j((String) gVar.m.b)) {
                    com.google.mlkit.common.internal.model.a.j(nVar.b, Color.parseColor(gVar.h), Color.parseColor((String) gVar.m.b));
                }
                String str3 = this.b;
                com.onetrust.otpublishers.headless.UI.fragment.m mVar2 = (com.onetrust.otpublishers.headless.UI.fragment.m) oVar.d;
                if (!zIsChecked2) {
                    ((HashMap) oVar.e).remove(str3);
                    mVar2.B = (HashMap) oVar.e;
                    str = "Purposes Removed : ";
                } else if (!((HashMap) oVar.e).containsKey(str3)) {
                    ((HashMap) oVar.e).put(str3, (String) this.e);
                    mVar2.B = (HashMap) oVar.e;
                    str = "Purposes Added : ";
                }
                OTLogger.c("OneTrust", 4, AbstractC0147y.d(str, str3));
                break;
        }
    }

    public /* synthetic */ ViewOnClickListenerC4054j(o oVar, n nVar, String str, String str2) {
        this.c = oVar;
        this.d = nVar;
        this.b = str;
        this.e = str2;
    }
}

package com.onetrust.otpublishers.headless.UI.adapter;

import android.graphics.Color;
import android.graphics.Typeface;
import android.view.ViewGroup;
import android.widget.TextView;
import androidx.recyclerview.widget.AbstractC1361d0;
import androidx.recyclerview.widget.F0;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.google.android.gms.internal.ads.C3;
import com.google.android.gms.internal.ads.Yh;
import com.google.android.gms.measurement.internal.Z;
import com.onetrust.otpublishers.headless.Public.DataModel.OTConfiguration;
import com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK;
import com.quizlet.quizletandroid.R;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.json.JSONArray;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class o extends AbstractC1361d0 {
    public final /* synthetic */ int a = 1;
    public final OTConfiguration b;
    public final Object c;
    public final Object d;
    public final Object e;
    public final Object f;

    public o(JSONArray jSONArray, List list, OTConfiguration oTConfiguration, androidx.work.impl.model.l lVar, com.onetrust.otpublishers.headless.UI.fragment.t tVar) {
        this.c = jSONArray;
        this.e = (Yh) lVar.b;
        this.b = oTConfiguration;
        this.f = tVar;
        this.d = new ArrayList(list);
    }

    public static void f(H h, C3 c3) throws NumberFormatException {
        String str = (String) ((androidx.navigation.internal.m) c3.g).f;
        assistantMode.utils.studiableMetadata.b.x(h.b, str);
        assistantMode.utils.studiableMetadata.b.x(h.f, str);
        assistantMode.utils.studiableMetadata.b.x(h.e, str);
        assistantMode.utils.studiableMetadata.b.x(h.g, str);
        assistantMode.utils.studiableMetadata.b.x(h.d, str);
        assistantMode.utils.studiableMetadata.b.x(h.i, str);
        assistantMode.utils.studiableMetadata.b.x(h.c, str);
        assistantMode.utils.studiableMetadata.b.x(h.h, str);
        assistantMode.utils.studiableMetadata.b.x(h.a, str);
    }

    public void d(TextView textView, androidx.navigation.internal.m mVar) throws NumberFormatException {
        OTConfiguration oTConfiguration;
        Typeface otTypeFaceMap;
        OTConfiguration oTConfiguration2;
        Typeface otTypeFaceMap2;
        switch (this.a) {
            case 0:
                com.google.android.gms.cloudmessaging.k kVar = (com.google.android.gms.cloudmessaging.k) mVar.d;
                String str = (String) kVar.e;
                if (com.onetrust.otpublishers.headless.Internal.a.j(str) || (oTConfiguration = this.b) == null || (otTypeFaceMap = oTConfiguration.getOtTypeFaceMap(str)) == null) {
                    int iA = com.google.android.gms.cloudmessaging.k.a(textView, kVar.b);
                    textView.setTypeface(!com.onetrust.otpublishers.headless.Internal.a.j((String) kVar.c) ? Typeface.create((String) kVar.c, iA) : Typeface.create(textView.getTypeface(), iA));
                } else {
                    textView.setTypeface(otTypeFaceMap);
                }
                if (!com.onetrust.otpublishers.headless.Internal.a.j((String) kVar.d)) {
                    textView.setTextSize(Float.parseFloat((String) kVar.d));
                }
                if (!com.onetrust.otpublishers.headless.Internal.a.j((String) mVar.b)) {
                    textView.setTextColor(Color.parseColor((String) mVar.b));
                }
                assistantMode.utils.studiableMetadata.b.x(textView, (String) mVar.f);
                break;
            default:
                com.google.android.gms.cloudmessaging.k kVar2 = (com.google.android.gms.cloudmessaging.k) mVar.d;
                String str2 = (String) kVar2.e;
                if (com.onetrust.otpublishers.headless.Internal.a.j(str2) || (oTConfiguration2 = this.b) == null || (otTypeFaceMap2 = oTConfiguration2.getOtTypeFaceMap(str2)) == null) {
                    int iA2 = com.google.android.gms.cloudmessaging.k.a(textView, kVar2.b);
                    textView.setTypeface(!com.onetrust.otpublishers.headless.Internal.a.j((String) kVar2.c) ? Typeface.create((String) kVar2.c, iA2) : Typeface.create(textView.getTypeface(), iA2));
                } else {
                    textView.setTypeface(otTypeFaceMap2);
                }
                if (!com.onetrust.otpublishers.headless.Internal.a.j((String) kVar2.d)) {
                    textView.setTextSize(Float.parseFloat((String) kVar2.d));
                }
                if (!com.onetrust.otpublishers.headless.Internal.a.j((String) mVar.b)) {
                    textView.setTextColor(Color.parseColor((String) mVar.b));
                }
                assistantMode.utils.studiableMetadata.b.x(textView, (String) mVar.f);
                break;
        }
    }

    public void g(H h, JSONObject jSONObject, JSONArray jSONArray) {
        if (!retrofit2.adapter.rxjava3.d.l(jSONArray)) {
            JSONObject jSONObject2 = (JSONObject) this.f;
            if (!retrofit2.adapter.rxjava3.d.o(jSONObject2)) {
                JSONArray jSONArray2 = new JSONArray();
                for (int i = 0; i < jSONArray.length(); i++) {
                    if (jSONArray.getInt(i) <= 10) {
                        jSONArray2.put(jSONObject2.getJSONObject(jSONArray.get(i).toString()));
                    }
                }
                androidx.navigation.internal.m mVar = (androidx.navigation.internal.m) ((C3) this.e).g;
                G g = new G(jSONArray2, !com.onetrust.otpublishers.headless.Internal.a.j((String) mVar.b) ? (String) mVar.b : jSONObject.optString("PcTextColor"), (C3) this.e, this.b, null, null);
                RecyclerView recyclerView = h.j;
                recyclerView.setLayoutManager(new LinearLayoutManager(recyclerView.getContext()));
                h.j.setAdapter(g);
                return;
            }
        }
        h.a.setVisibility(8);
    }

    /* JADX WARN: Code restructure failed: missing block: B:6:0x0014, code lost:
    
        com.onetrust.otpublishers.headless.Internal.Log.OTLogger.c("OneTrust", 6, "Error on populating disclosures");
     */
    @Override // androidx.recyclerview.widget.AbstractC1361d0
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final int getItemCount() {
        /*
            r3 = this;
            int r0 = r3.a
            switch(r0) {
                case 0: goto L27;
                case 1: goto L1e;
                default: goto L5;
            }
        L5:
            java.lang.Object r0 = r3.d     // Catch: org.json.JSONException -> L14
            org.json.JSONObject r0 = (org.json.JSONObject) r0     // Catch: org.json.JSONException -> L14
            java.lang.String r1 = "disclosures"
            org.json.JSONArray r0 = r0.getJSONArray(r1)     // Catch: org.json.JSONException -> L14
            int r0 = r0.length()     // Catch: org.json.JSONException -> L14
            goto L1d
        L14:
            r0 = 6
            java.lang.String r1 = "OneTrust"
            java.lang.String r2 = "Error on populating disclosures"
            com.onetrust.otpublishers.headless.Internal.Log.OTLogger.c(r1, r0, r2)
            r0 = 0
        L1d:
            return r0
        L1e:
            java.lang.Object r0 = r3.c
            org.json.JSONArray r0 = (org.json.JSONArray) r0
            int r0 = r0.length()
            return r0
        L27:
            java.lang.Object r0 = r3.c
            org.json.JSONArray r0 = (org.json.JSONArray) r0
            int r0 = r0.length()
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.UI.adapter.o.getItemCount():int");
    }

    public void h(JSONObject jSONObject, H h) throws NumberFormatException {
        String strOptString;
        OTConfiguration oTConfiguration = this.b;
        C3 c3 = (C3) this.e;
        try {
            if (c3 != null) {
                androidx.navigation.internal.m mVar = (androidx.navigation.internal.m) c3.g;
                strOptString = !com.onetrust.otpublishers.headless.Internal.a.j((String) mVar.b) ? (String) mVar.b : jSONObject.optString("PcTextColor");
                if (!com.onetrust.otpublishers.headless.Internal.a.j((String) ((com.google.android.gms.cloudmessaging.k) ((androidx.navigation.internal.m) c3.g).d).d)) {
                    float f = Float.parseFloat((String) ((com.google.android.gms.cloudmessaging.k) ((androidx.navigation.internal.m) c3.g).d).d);
                    h.b.setTextSize(f);
                    h.f.setTextSize(f);
                    h.e.setTextSize(f);
                    h.g.setTextSize(f);
                    h.d.setTextSize(f);
                    h.i.setTextSize(f);
                    h.c.setTextSize(f);
                    h.h.setTextSize(f);
                    h.a.setTextSize(f);
                }
                f(h, c3);
                com.google.android.gms.cloudmessaging.k kVar = (com.google.android.gms.cloudmessaging.k) ((androidx.navigation.internal.m) c3.g).d;
                assistantMode.utils.studiableMetadata.b.w(h.b, kVar, oTConfiguration);
                assistantMode.utils.studiableMetadata.b.w(h.f, kVar, oTConfiguration);
                assistantMode.utils.studiableMetadata.b.w(h.e, kVar, oTConfiguration);
                assistantMode.utils.studiableMetadata.b.w(h.g, kVar, oTConfiguration);
                assistantMode.utils.studiableMetadata.b.w(h.d, kVar, oTConfiguration);
                assistantMode.utils.studiableMetadata.b.w(h.i, kVar, oTConfiguration);
                assistantMode.utils.studiableMetadata.b.w(h.c, kVar, oTConfiguration);
                assistantMode.utils.studiableMetadata.b.w(h.h, kVar, oTConfiguration);
                assistantMode.utils.studiableMetadata.b.w(h.a, kVar, oTConfiguration);
            } else {
                strOptString = jSONObject.optString("PcTextColor");
            }
            h.b.setTextColor(Color.parseColor(strOptString));
            h.f.setTextColor(Color.parseColor(strOptString));
            h.e.setTextColor(Color.parseColor(strOptString));
            h.g.setTextColor(Color.parseColor(strOptString));
            h.d.setTextColor(Color.parseColor(strOptString));
            h.i.setTextColor(Color.parseColor(strOptString));
            h.c.setTextColor(Color.parseColor(strOptString));
            h.h.setTextColor(Color.parseColor(strOptString));
            h.a.setTextColor(Color.parseColor(strOptString));
        } catch (Exception e) {
            Z.n("Error while applying styles to Vendor disclosures, err : ", e, "OneTrust", 6);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:23:0x008e A[Catch: Exception -> 0x004f, TRY_ENTER, TryCatch #0 {Exception -> 0x004f, blocks: (B:5:0x000f, B:7:0x0023, B:9:0x002c, B:12:0x0047, B:18:0x0065, B:20:0x0075, B:23:0x008e, B:25:0x00a0, B:28:0x00b5, B:30:0x00c7, B:29:0x00c1, B:24:0x009a, B:15:0x0053, B:17:0x0061, B:19:0x006d), top: B:80:0x000f }] */
    /* JADX WARN: Removed duplicated region for block: B:24:0x009a A[Catch: Exception -> 0x004f, TryCatch #0 {Exception -> 0x004f, blocks: (B:5:0x000f, B:7:0x0023, B:9:0x002c, B:12:0x0047, B:18:0x0065, B:20:0x0075, B:23:0x008e, B:25:0x00a0, B:28:0x00b5, B:30:0x00c7, B:29:0x00c1, B:24:0x009a, B:15:0x0053, B:17:0x0061, B:19:0x006d), top: B:80:0x000f }] */
    /* JADX WARN: Removed duplicated region for block: B:28:0x00b5 A[Catch: Exception -> 0x004f, TRY_ENTER, TryCatch #0 {Exception -> 0x004f, blocks: (B:5:0x000f, B:7:0x0023, B:9:0x002c, B:12:0x0047, B:18:0x0065, B:20:0x0075, B:23:0x008e, B:25:0x00a0, B:28:0x00b5, B:30:0x00c7, B:29:0x00c1, B:24:0x009a, B:15:0x0053, B:17:0x0061, B:19:0x006d), top: B:80:0x000f }] */
    /* JADX WARN: Removed duplicated region for block: B:29:0x00c1 A[Catch: Exception -> 0x004f, TryCatch #0 {Exception -> 0x004f, blocks: (B:5:0x000f, B:7:0x0023, B:9:0x002c, B:12:0x0047, B:18:0x0065, B:20:0x0075, B:23:0x008e, B:25:0x00a0, B:28:0x00b5, B:30:0x00c7, B:29:0x00c1, B:24:0x009a, B:15:0x0053, B:17:0x0061, B:19:0x006d), top: B:80:0x000f }] */
    @Override // androidx.recyclerview.widget.AbstractC1361d0
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void onBindViewHolder(androidx.recyclerview.widget.F0 r13, int r14) throws org.json.JSONException, java.lang.NumberFormatException {
        /*
            Method dump skipped, instructions count: 708
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.UI.adapter.o.onBindViewHolder(androidx.recyclerview.widget.F0, int):void");
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final F0 onCreateViewHolder(ViewGroup viewGroup, int i) {
        switch (this.a) {
            case 0:
                return new n(Z.c(viewGroup, R.layout.ot_purpose_list_item, viewGroup, false));
            case 1:
                return new v(Z.c(viewGroup, R.layout.ot_sdk_list_filter_item, viewGroup, false));
            default:
                return new H(Z.c(viewGroup, R.layout.ot_vendor_disclosure_item, viewGroup, false));
        }
    }

    public o(JSONArray jSONArray, Map map, com.onetrust.otpublishers.headless.UI.UIProperty.g gVar, OTConfiguration oTConfiguration, com.onetrust.otpublishers.headless.UI.fragment.m mVar) {
        this.e = new HashMap();
        this.c = jSONArray;
        this.f = gVar;
        this.b = oTConfiguration;
        this.d = mVar;
        this.e = new HashMap(map);
    }

    public o(JSONObject jSONObject, OTPublishersHeadlessSDK oTPublishersHeadlessSDK, C3 c3, JSONObject jSONObject2, OTConfiguration oTConfiguration) {
        this.d = jSONObject;
        this.c = oTPublishersHeadlessSDK;
        this.e = c3;
        this.f = jSONObject2;
        this.b = oTConfiguration;
    }
}

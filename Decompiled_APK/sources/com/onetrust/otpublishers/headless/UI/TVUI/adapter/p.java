package com.onetrust.otpublishers.headless.UI.TVUI.adapter;

import android.R;
import android.content.res.ColorStateList;
import android.graphics.Color;
import android.graphics.Typeface;
import android.view.ViewGroup;
import android.widget.CheckBox;
import android.widget.CompoundButton;
import android.widget.TextView;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.cardview.widget.CardView;
import androidx.recyclerview.widget.AbstractC1361d0;
import androidx.recyclerview.widget.F0;
import com.google.android.gms.internal.ads.C3;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3617f4;
import com.google.android.gms.measurement.internal.Z;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.onetrust.otpublishers.headless.Public.DataModel.OTConfiguration;
import com.onetrust.otpublishers.headless.UI.adapter.I;
import java.util.ArrayList;
import java.util.HashMap;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class p extends AbstractC1361d0 {
    public final /* synthetic */ int a = 0;
    public final JSONArray b;
    public final Object c;
    public final Object d;
    public Object e;

    public p(JSONArray jSONArray, String str, ArrayList arrayList, com.onetrust.otpublishers.headless.UI.TVUI.fragments.m mVar) {
        new ArrayList();
        this.b = jSONArray;
        this.c = str;
        this.d = mVar;
        this.e = arrayList;
    }

    public static void d(CheckBox checkBox, int i) {
        checkBox.setButtonTintList(new ColorStateList(new int[][]{new int[]{R.attr.state_checked}, new int[0]}, new int[]{i, i}));
    }

    public static void g(CheckBox checkBox, int i) {
        checkBox.setButtonTintList(new ColorStateList(new int[][]{new int[]{R.attr.state_checked}, new int[0]}, new int[]{i, i}));
    }

    public void f(TextView textView, String str) throws NumberFormatException {
        OTConfiguration oTConfiguration;
        Typeface otTypeFaceMap;
        C3 c3 = (C3) this.d;
        if (c3 == null) {
            return;
        }
        androidx.navigation.internal.m mVar = (androidx.navigation.internal.m) c3.g;
        if (!com.onetrust.otpublishers.headless.Internal.a.j(str)) {
            textView.setText(str);
        }
        textView.setTextColor(Color.parseColor(!com.onetrust.otpublishers.headless.Internal.a.j((String) mVar.b) ? (String) mVar.b : ((JSONObject) this.c).optString("PcTextColor")));
        assistantMode.utils.studiableMetadata.b.x(textView, (String) mVar.f);
        if (!com.onetrust.otpublishers.headless.Internal.a.j((String) ((com.google.android.gms.cloudmessaging.k) mVar.d).d)) {
            textView.setTextSize(Float.parseFloat((String) ((com.google.android.gms.cloudmessaging.k) mVar.d).d));
        }
        com.google.android.gms.cloudmessaging.k kVar = (com.google.android.gms.cloudmessaging.k) mVar.d;
        String str2 = (String) kVar.e;
        if (!com.onetrust.otpublishers.headless.Internal.a.j(str2) && (oTConfiguration = (OTConfiguration) this.e) != null && (otTypeFaceMap = oTConfiguration.getOtTypeFaceMap(str2)) != null) {
            textView.setTypeface(otTypeFaceMap);
        } else {
            int iA = com.google.android.gms.cloudmessaging.k.a(textView, kVar.b);
            textView.setTypeface(!com.onetrust.otpublishers.headless.Internal.a.j((String) kVar.c) ? Typeface.create((String) kVar.c, iA) : Typeface.create(textView.getTypeface(), iA));
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:6:0x000c, code lost:
    
        com.onetrust.otpublishers.headless.Internal.Log.OTLogger.c("OneTrust", 6, "Error on populating domains used");
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
                case 0: goto L1d;
                case 1: goto L16;
                default: goto L5;
            }
        L5:
            org.json.JSONArray r0 = r3.b     // Catch: java.lang.Exception -> Lc
            int r0 = r0.length()     // Catch: java.lang.Exception -> Lc
            goto L15
        Lc:
            r0 = 6
            java.lang.String r1 = "OneTrust"
            java.lang.String r2 = "Error on populating domains used"
            com.onetrust.otpublishers.headless.Internal.Log.OTLogger.c(r1, r0, r2)
            r0 = 0
        L15:
            return r0
        L16:
            org.json.JSONArray r0 = r3.b
            int r0 = r0.length()
            return r0
        L1d:
            org.json.JSONArray r0 = r3.b
            int r0 = r0.length()
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.UI.TVUI.adapter.p.getItemCount():int");
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final void onBindViewHolder(F0 f0, int i) throws JSONException, NumberFormatException {
        switch (this.a) {
            case 0:
                o oVar = (o) f0;
                String str = (String) this.c;
                oVar.setIsRecyclable(false);
                CardView cardView = oVar.d;
                TextView textView = oVar.a;
                CheckBox checkBox = oVar.b;
                boolean z = false;
                try {
                    com.onetrust.otpublishers.headless.UI.TVUI.datautils.c cVarI = com.onetrust.otpublishers.headless.UI.TVUI.datautils.c.i();
                    JSONObject jSONObject = this.b.getJSONObject(oVar.getAdapterPosition());
                    textView.setText(jSONObject.getString("GroupName"));
                    String strOptString = jSONObject.optString("CustomGroupId", "");
                    int i2 = 0;
                    while (true) {
                        if (i2 < ((ArrayList) this.e).size()) {
                            if (((String) ((ArrayList) this.e).get(i2)).trim().equals(strOptString)) {
                                z = true;
                            } else {
                                i2++;
                            }
                        }
                    }
                    checkBox.setChecked(z);
                    String strJ = AbstractC3617f4.j(cVarI.a());
                    oVar.c.setBackgroundColor(Color.parseColor(strJ));
                    textView.setTextColor(Color.parseColor(str));
                    d(checkBox, Color.parseColor(str));
                    cardView.setCardElevation(1.0f);
                    oVar.itemView.setOnFocusChangeListener(new f(this, oVar, cVarI, strJ, 1));
                    cardView.setOnKeyListener(new m(oVar, 0));
                    checkBox.setOnCheckedChangeListener(new n(this, oVar, strOptString, 0));
                    break;
                } catch (JSONException e) {
                    Z.p("error while parsing ", e, "OneTrust", 6);
                    return;
                }
            case 1:
                final t tVar = (t) f0;
                String str2 = (String) this.c;
                boolean zContainsKey = false;
                tVar.setIsRecyclable(false);
                CardView cardView2 = tVar.d;
                TextView textView2 = tVar.a;
                CheckBox checkBox2 = tVar.b;
                try {
                    com.onetrust.otpublishers.headless.UI.TVUI.datautils.c cVarI2 = com.onetrust.otpublishers.headless.UI.TVUI.datautils.c.i();
                    JSONObject jSONObject2 = this.b.getJSONObject(tVar.getAdapterPosition());
                    textView2.setText(jSONObject2.getString("GroupName"));
                    final String strOptString2 = jSONObject2.optString("CustomGroupId", "");
                    OTLogger.c("OneTrust", 4, "Purposes to pass on apply filters : " + ((HashMap) this.e));
                    if (((HashMap) this.e) != null) {
                        OTLogger.c("OneTrust", 4, "Purposes to pass on apply filters : " + ((HashMap) this.e));
                        zContainsKey = ((HashMap) this.e).containsKey(strOptString2);
                    }
                    checkBox2.setChecked(zContainsKey);
                    String strJ2 = AbstractC3617f4.j(cVarI2.a());
                    tVar.c.setBackgroundColor(Color.parseColor(strJ2));
                    textView2.setTextColor(Color.parseColor(str2));
                    g(checkBox2, Color.parseColor(str2));
                    cardView2.setCardElevation(1.0f);
                    tVar.itemView.setOnFocusChangeListener(new f(this, tVar, cVarI2, strJ2, 2));
                    cardView2.setOnKeyListener(new m(tVar, 1));
                    final String string = jSONObject2.getString("Type");
                    checkBox2.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() { // from class: com.onetrust.otpublishers.headless.UI.TVUI.adapter.s
                        @Override // android.widget.CompoundButton.OnCheckedChangeListener
                        public final void onCheckedChanged(CompoundButton compoundButton, boolean z2) {
                            String str3;
                            p pVar = this.a;
                            boolean zIsChecked = tVar.b.isChecked();
                            String str4 = strOptString2;
                            com.onetrust.otpublishers.headless.UI.TVUI.fragments.q qVar = (com.onetrust.otpublishers.headless.UI.TVUI.fragments.q) pVar.d;
                            if (!zIsChecked) {
                                ((HashMap) pVar.e).remove(str4);
                                qVar.g = (HashMap) pVar.e;
                                str3 = "Purposes Removed : ";
                            } else {
                                if (((HashMap) pVar.e).containsKey(str4)) {
                                    return;
                                }
                                ((HashMap) pVar.e).put(str4, string);
                                qVar.g = (HashMap) pVar.e;
                                str3 = "Purposes Added : ";
                            }
                            OTLogger.c("OneTrust", 4, AbstractC0147y.d(str3, str4));
                        }
                    });
                    break;
                } catch (JSONException e2) {
                    Z.p("error while parsing ", e2, "OneTrust", 6);
                    return;
                }
            default:
                I i3 = (I) f0;
                try {
                    JSONObject jSONObject3 = this.b.getJSONObject(i3.getAdapterPosition());
                    JSONObject jSONObject4 = (JSONObject) this.c;
                    if (jSONObject4 != null && !retrofit2.adapter.rxjava3.d.o(jSONObject3)) {
                        boolean zHas = jSONObject3.has("domain");
                        TextView textView3 = i3.b;
                        TextView textView4 = i3.a;
                        if (!zHas || com.onetrust.otpublishers.headless.Internal.a.j(jSONObject3.optString("domain"))) {
                            textView4.setVisibility(8);
                            textView3.setVisibility(8);
                        } else {
                            f(textView4, jSONObject4.optString("PCenterVendorListStorageDomain"));
                            f(textView3, jSONObject3.optString("domain"));
                        }
                        boolean zHas2 = jSONObject3.has("use");
                        TextView textView5 = i3.d;
                        TextView textView6 = i3.c;
                        if (zHas2 && !com.onetrust.otpublishers.headless.Internal.a.j(jSONObject3.optString("use"))) {
                            f(textView6, jSONObject4.optString("PCVLSUse"));
                            f(textView5, jSONObject3.optString("use"));
                            break;
                        } else {
                            textView6.setVisibility(8);
                            textView5.setVisibility(8);
                            break;
                        }
                    }
                } catch (JSONException e3) {
                    Z.p("Error on populating disclosures, err : ", e3, "OneTrust", 6);
                }
                break;
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final F0 onCreateViewHolder(ViewGroup viewGroup, int i) {
        switch (this.a) {
            case 0:
                return new o(Z.c(viewGroup, com.quizlet.quizletandroid.R.layout.ot_tv_purpose_filter_item, viewGroup, false));
            case 1:
                return new t(Z.c(viewGroup, com.quizlet.quizletandroid.R.layout.ot_tv_purpose_filter_item, viewGroup, false));
            default:
                return new I(Z.c(viewGroup, com.quizlet.quizletandroid.R.layout.ot_vendor_domains_used_item, viewGroup, false));
        }
    }

    public p(JSONArray jSONArray, String str, HashMap map, com.onetrust.otpublishers.headless.UI.TVUI.fragments.q qVar) {
        this.e = new HashMap();
        this.b = jSONArray;
        this.c = str;
        this.d = qVar;
        this.e = new HashMap(map);
    }

    public p(JSONArray jSONArray, JSONObject jSONObject, C3 c3, OTConfiguration oTConfiguration) {
        this.b = jSONArray;
        this.c = jSONObject;
        this.d = c3;
        this.e = oTConfiguration;
    }
}

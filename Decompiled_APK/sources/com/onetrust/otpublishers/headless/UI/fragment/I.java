package com.onetrust.otpublishers.headless.UI.fragment;

import android.app.Dialog;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.res.Configuration;
import android.graphics.Color;
import android.graphics.PorterDuff;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.CompoundButton;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.appcompat.widget.SwitchCompat;
import androidx.camera.camera2.internal.T;
import androidx.core.view.V;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.google.android.gms.internal.ads.C3;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3705q4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.Q;
import com.google.android.gms.measurement.internal.Z;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.onetrust.otpublishers.headless.Public.DataModel.OTConfiguration;
import com.onetrust.otpublishers.headless.Public.Keys.OTFragmentTags;
import com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK;
import com.onetrust.otpublishers.headless.Public.OTThemeConstants;
import com.onetrust.otpublishers.headless.Public.OTVendorListMode;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONException;
import org.json.JSONObject;
import retrofit2.C5177b;

/* loaded from: classes2.dex */
public class I extends com.google.android.material.bottomsheet.i implements View.OnClickListener {
    public TextView A;
    public androidx.room.s A1;
    public TextView B;
    public assistantMode.utils.studiableMetadata.b B1;
    public TextView C;
    public com.onetrust.otpublishers.headless.Internal.Event.a C1;
    public TextView D;
    public TextView D1;
    public TextView E;
    public com.onetrust.otpublishers.headless.UI.mobiledatautils.b E1;
    public TextView F;
    public TextView G;
    public TextView H;
    public TextView I;
    public TextView J;
    public TextView K;
    public RecyclerView L;
    public RelativeLayout M;
    public com.google.android.material.bottomsheet.h V;
    public ImageView W;
    public Context X;
    public OTPublishersHeadlessSDK Y;
    public JSONObject Z;
    public SwitchCompat c1;
    public SwitchCompat d1;
    public RecyclerView e1;
    public RecyclerView f1;
    public RecyclerView g1;
    public RecyclerView h1;
    public RecyclerView i1;
    public RecyclerView j1;
    public RecyclerView k1;
    public RelativeLayout l1;
    public RelativeLayout m1;
    public LinearLayout n1;
    public LinearLayout o1;
    public String p1;
    public String q;
    public w q1;
    public String r;
    public View r1;
    public TextView s;
    public View s1;
    public TextView t;
    public String t1;
    public TextView u;
    public String u1;
    public TextView v;
    public String v1;
    public TextView w;
    public String w1;
    public TextView x;
    public String x1;
    public TextView y;
    public C3 y1;
    public TextView z;
    public OTConfiguration z1;

    @Override // com.google.android.material.bottomsheet.i, androidx.appcompat.app.E, androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t
    public final Dialog K(Bundle bundle) {
        Dialog dialogK = super.K(bundle);
        dialogK.setOnShowListener(new com.onetrust.otpublishers.headless.UI.TVUI.fragments.e(this, 13));
        return dialogK;
    }

    public final void Q(String str, String str2, String str3, String str4, String str5, String str6) {
        this.s.setTextColor(Color.parseColor(this.u1));
        this.D.setTextColor(Color.parseColor(this.u1));
        this.E.setTextColor(Color.parseColor(str2));
        this.F.setTextColor(Color.parseColor(str3));
        this.m1.setBackgroundColor(Color.parseColor(str));
        this.l1.setBackgroundColor(Color.parseColor(str));
        this.o1.setBackgroundColor(Color.parseColor(str));
        this.n1.setBackgroundColor(Color.parseColor(str));
        this.W.setColorFilter(Color.parseColor(str5), PorterDuff.Mode.SRC_IN);
        this.t.setTextColor(Color.parseColor(str6));
        this.u.setTextColor(Color.parseColor(str6));
        this.v.setTextColor(Color.parseColor(str4));
        this.w.setTextColor(Color.parseColor(str4));
        this.x.setTextColor(Color.parseColor(str4));
        this.B.setTextColor(Color.parseColor(str4));
        this.C.setTextColor(Color.parseColor(str4));
        this.A.setTextColor(Color.parseColor(str4));
        this.z.setTextColor(Color.parseColor(str4));
        this.G.setTextColor(Color.parseColor(str4));
        this.I.setTextColor(Color.parseColor(this.t1));
        this.y.setTextColor(Color.parseColor(this.t1));
        this.H.setTextColor(Color.parseColor(this.t1));
        this.J.setTextColor(Color.parseColor(str4));
        this.K.setTextColor(Color.parseColor(str4));
    }

    public final void R(JSONObject jSONObject, JSONObject jSONObject2) throws JSONException {
        JSONObject jSONObject3 = null;
        if (this.Z.getJSONArray("purposes").length() > 0) {
            this.v.setVisibility(0);
            TextView textView = this.v;
            textView.setText(jSONObject.optString("BConsentPurposesText", getString(R.string.ot_vd_purposes_consent_title)));
            V.p(textView, true);
            this.e1.setVisibility(0);
            this.e1.setLayoutManager(new LinearLayoutManager(this.X));
            this.e1.setAdapter(new com.onetrust.otpublishers.headless.UI.adapter.G(this.Z.getJSONArray("purposes"), this.t1, this.y1, this.z1, (jSONObject2 == null || !jSONObject2.has("purposes")) ? null : jSONObject2.getJSONObject("purposes"), jSONObject.optString("PCenterVendorListLifespanDays", "Days")));
            this.e1.setNestedScrollingEnabled(false);
        }
        if (this.Z.getJSONArray("legIntPurposes").length() > 0) {
            this.z.setVisibility(0);
            TextView textView2 = this.z;
            textView2.setText(jSONObject.optString("BLegitimateInterestPurposesText", getString(R.string.ot_vd_LIPurposes_consent_title)));
            V.p(textView2, true);
            this.g1.setVisibility(0);
            this.g1.setLayoutManager(new LinearLayoutManager(this.X));
            this.g1.setAdapter(new com.onetrust.otpublishers.headless.UI.adapter.G(this.Z.getJSONArray("legIntPurposes"), this.t1, this.y1, this.z1, null, null));
            this.g1.setNestedScrollingEnabled(false);
        }
        if (this.Z.getJSONArray("features").length() > 0) {
            this.A.setVisibility(0);
            TextView textView3 = this.A;
            textView3.setText(jSONObject.optString("BFeaturesText", getString(R.string.ot_vd_feature_consent_title)));
            V.p(textView3, true);
            this.h1.setVisibility(0);
            this.h1.setLayoutManager(new LinearLayoutManager(this.X));
            this.h1.setAdapter(new com.onetrust.otpublishers.headless.UI.adapter.G(this.Z.getJSONArray("features"), this.t1, this.y1, this.z1, null, null));
            this.h1.setNestedScrollingEnabled(false);
        }
        if (this.Z.getJSONArray("specialFeatures").length() > 0) {
            this.C.setVisibility(0);
            TextView textView4 = this.C;
            textView4.setText(jSONObject.optString("BSpecialFeaturesText", getString(R.string.ot_vd_SpFeature_consent_title)));
            V.p(textView4, true);
            this.i1.setVisibility(0);
            this.i1.setLayoutManager(new LinearLayoutManager(this.X));
            this.i1.setAdapter(new com.onetrust.otpublishers.headless.UI.adapter.G(this.Z.getJSONArray("specialFeatures"), this.t1, this.y1, this.z1, null, null));
            this.i1.setNestedScrollingEnabled(false);
        }
        if (this.Z.getJSONArray("specialPurposes").length() > 0) {
            this.B.setVisibility(0);
            TextView textView5 = this.B;
            textView5.setText(jSONObject.optString("BSpecialPurposesText", getString(R.string.ot_vd_SpPurposes_consent_title)));
            V.p(textView5, true);
            this.j1.setVisibility(0);
            this.j1.setLayoutManager(new LinearLayoutManager(this.X));
            if (jSONObject2 != null && jSONObject2.has("purposes")) {
                jSONObject3 = jSONObject2.getJSONObject("specialPurposes");
            }
            this.j1.setAdapter(new com.onetrust.otpublishers.headless.UI.adapter.G(this.Z.getJSONArray("specialPurposes"), this.t1, this.y1, this.z1, jSONObject3, jSONObject.optString("PCenterVendorListLifespanDays", "Days")));
            this.j1.setNestedScrollingEnabled(false);
        }
        if (this.Z.getJSONArray("dataDeclaration").length() > 0) {
            this.w.setText(jSONObject.optString("PCVListDataDeclarationText", getString(R.string.ot_vd_data_declaration_title)));
            this.w.setVisibility(0);
            V.p(this.w, true);
            this.f1.setVisibility(0);
            this.f1.setLayoutManager(new LinearLayoutManager(this.X));
            this.f1.setAdapter(new com.onetrust.otpublishers.headless.UI.adapter.G(this.Z.getJSONArray("dataDeclaration"), this.t1, this.y1, this.z1, null, null));
            this.f1.setNestedScrollingEnabled(false);
        }
    }

    public final void S() throws NumberFormatException {
        assistantMode.utils.studiableMetadata.b.x(this.s, (String) ((androidx.navigation.internal.m) this.y1.e).f);
        assistantMode.utils.studiableMetadata.b.x(this.E, (String) ((androidx.navigation.internal.m) this.y1.h).f);
        assistantMode.utils.studiableMetadata.b.x(this.F, (String) ((androidx.navigation.internal.m) this.y1.i).f);
        String str = (String) ((androidx.navigation.internal.m) this.y1.f).f;
        assistantMode.utils.studiableMetadata.b.x(this.v, str);
        assistantMode.utils.studiableMetadata.b.x(this.w, str);
        assistantMode.utils.studiableMetadata.b.x(this.x, str);
        assistantMode.utils.studiableMetadata.b.x(this.A, str);
        assistantMode.utils.studiableMetadata.b.x(this.C, str);
        assistantMode.utils.studiableMetadata.b.x(this.B, str);
        assistantMode.utils.studiableMetadata.b.x(this.z, str);
        assistantMode.utils.studiableMetadata.b.x(this.G, str);
        assistantMode.utils.studiableMetadata.b.x(this.J, str);
        assistantMode.utils.studiableMetadata.b.x(this.K, str);
        String str2 = (String) ((androidx.navigation.internal.m) this.y1.g).f;
        assistantMode.utils.studiableMetadata.b.x(this.H, str2);
        assistantMode.utils.studiableMetadata.b.x(this.I, str2);
    }

    public final void T(JSONObject jSONObject) throws NumberFormatException {
        try {
            int iD = assistantMode.utils.studiableMetadata.b.d(this.X, this.z1);
            com.onetrust.otpublishers.headless.UI.UIProperty.f fVar = new com.onetrust.otpublishers.headless.UI.UIProperty.f(this.X, iD);
            this.y1 = fVar.f();
            this.A1 = fVar.a.c();
            a(jSONObject);
            String str = (String) ((androidx.navigation.internal.m) this.y1.f).b;
            String strOptString = jSONObject.optString("PcTextColor");
            String str2 = "#696969";
            if (!com.onetrust.otpublishers.headless.Internal.a.j(str)) {
                strOptString = str;
            } else if (com.onetrust.otpublishers.headless.Internal.a.j(strOptString)) {
                strOptString = iD == 11 ? "#FFFFFF" : "#696969";
            }
            String str3 = (String) ((androidx.navigation.internal.m) this.y1.h).b;
            String strOptString2 = jSONObject.optString("PcTextColor");
            if (com.onetrust.otpublishers.headless.Internal.a.j(str3)) {
                str3 = !com.onetrust.otpublishers.headless.Internal.a.j(strOptString2) ? strOptString2 : iD == 11 ? "#FFFFFF" : "#696969";
            }
            String str4 = (String) ((androidx.navigation.internal.m) this.y1.i).b;
            String strOptString3 = jSONObject.optString("PcTextColor");
            if (com.onetrust.otpublishers.headless.Internal.a.j(str4)) {
                str4 = !com.onetrust.otpublishers.headless.Internal.a.j(strOptString3) ? strOptString3 : iD == 11 ? "#FFFFFF" : "#696969";
            }
            String str5 = (String) this.y1.a;
            String strOptString4 = jSONObject.optString("PcBackgroundColor");
            if (com.onetrust.otpublishers.headless.Internal.a.j(str5)) {
                str5 = !com.onetrust.otpublishers.headless.Internal.a.j(strOptString4) ? strOptString4 : iD == 11 ? "#2F2F2F" : "#FFFFFF";
            }
            String str6 = (String) this.y1.k;
            String strOptString5 = jSONObject.optString("PcTextColor");
            if (!com.onetrust.otpublishers.headless.Internal.a.j(str6)) {
                str2 = str6;
            } else if (!com.onetrust.otpublishers.headless.Internal.a.j(strOptString5)) {
                str2 = strOptString5;
            } else if (iD == 11) {
                str2 = "#FFFFFF";
            }
            X();
            assistantMode.utils.studiableMetadata.b bVar = this.B1;
            androidx.navigation.internal.m mVar = (androidx.navigation.internal.m) ((com.quizlet.data.repository.user.e) this.y1.j).b;
            String strOptString6 = jSONObject.optString("PcLinksTextColor");
            bVar.getClass();
            if (!com.onetrust.otpublishers.headless.Internal.a.j((String) mVar.b)) {
                strOptString6 = (String) mVar.b;
            }
            androidx.room.s sVar = this.A1;
            if (sVar == null || sVar.c) {
                TextView textView = this.t;
                textView.setPaintFlags(textView.getPaintFlags() | 8);
                TextView textView2 = this.u;
                textView2.setPaintFlags(textView2.getPaintFlags() | 8);
            }
            a();
            S();
            W();
            Q(str5, str3, str4, strOptString, str2, strOptString6);
        } catch (JSONException e) {
            Z.p("Error while applying styles to Vendor details, err : ", e, "OneTrust", 6);
        }
    }

    public final void U(JSONObject jSONObject, JSONObject jSONObject2) throws JSONException {
        if (com.onetrust.otpublishers.headless.Internal.a.l(this.E1.M)) {
            this.x.setText(jSONObject2.optString("PCVListDataRetentionText", getString(R.string.ot_vd_data_retention_title)));
            this.x.setVisibility(0);
            V.p(this.x, true);
            if (jSONObject == null || !jSONObject.has("stdRetention") || com.onetrust.otpublishers.headless.Internal.a.j(jSONObject.getString("stdRetention"))) {
                return;
            }
            String string = jSONObject.getString("stdRetention");
            if (com.onetrust.otpublishers.headless.Internal.a.j(string) || Integer.parseInt(string) < 0) {
                return;
            }
            this.y.setVisibility(0);
            this.y.setText(jSONObject2.optString("PCVListStdRetentionText", getString(R.string.ot_vd_standard_data_retention)) + " (" + string + " " + jSONObject2.optString("PCenterVendorListLifespanDays") + ")");
        }
    }

    public final void V(JSONObject jSONObject) throws JSONException {
        com.onetrust.otpublishers.headless.Internal.Preferences.f fVar;
        if (!this.Z.has("deviceStorageDisclosureUrl")) {
            this.M.setVisibility(8);
            return;
        }
        this.J.setVisibility(8);
        this.J.setText(jSONObject.optString("PCenterVendorListDisclosure") + ":");
        String string = this.Z.getString("deviceStorageDisclosureUrl");
        Context context = this.X;
        boolean z = false;
        SharedPreferences sharedPreferences = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
        if (Q.a(context)) {
            fVar = new com.onetrust.otpublishers.headless.Internal.Preferences.f(context, sharedPreferences, sharedPreferences.getString("OT_ACTIVE_PROFILE_ID", ""));
            z = true;
        } else {
            fVar = null;
        }
        if (z) {
            sharedPreferences = fVar;
        }
        String string2 = sharedPreferences.getString("OT_IAB_PURPOSES_TRANSLATED", "");
        JSONObject jSONObject2 = new JSONObject();
        if (!com.onetrust.otpublishers.headless.Internal.a.j(string2)) {
            jSONObject2 = new JSONObject(string2);
        }
        JSONObject jSONObject3 = new JSONObject();
        if (jSONObject2.has("purposes")) {
            jSONObject3 = jSONObject2.getJSONObject("purposes");
        }
        T t = new T(this, jSONObject3, jSONObject, 18);
        new com.onetrust.otpublishers.headless.Internal.Preferences.d(this.X);
        OTLogger.c("NetworkRequestHandler", 3, "IAB Vendor Disclosure API called ");
        com.quizlet.data.repository.explanations.textbook.a aVar = new com.quizlet.data.repository.explanations.textbook.a(8);
        aVar.c("https://geolocation.1trust.app/");
        aVar.b(new C5177b(2));
        aVar.a = new okhttp3.A(new okhttp3.z());
        ((com.onetrust.otpublishers.headless.Internal.Network.a) aVar.e().b(com.onetrust.otpublishers.headless.Internal.Network.a.class)).a(string).j(new androidx.work.impl.model.e(14, new JSONObject[1], t));
    }

    public final void W() {
        com.google.android.gms.cloudmessaging.k kVar = (com.google.android.gms.cloudmessaging.k) ((androidx.navigation.internal.m) this.y1.e).d;
        assistantMode.utils.studiableMetadata.b bVar = this.B1;
        TextView textView = this.s;
        OTConfiguration oTConfiguration = this.z1;
        bVar.getClass();
        assistantMode.utils.studiableMetadata.b.w(textView, kVar, oTConfiguration);
        com.google.android.gms.cloudmessaging.k kVar2 = (com.google.android.gms.cloudmessaging.k) ((androidx.navigation.internal.m) ((com.quizlet.data.repository.user.e) this.y1.j).b).d;
        assistantMode.utils.studiableMetadata.b bVar2 = this.B1;
        TextView textView2 = this.t;
        OTConfiguration oTConfiguration2 = this.z1;
        bVar2.getClass();
        assistantMode.utils.studiableMetadata.b.w(textView2, kVar2, oTConfiguration2);
        assistantMode.utils.studiableMetadata.b bVar3 = this.B1;
        TextView textView3 = this.u;
        OTConfiguration oTConfiguration3 = this.z1;
        bVar3.getClass();
        assistantMode.utils.studiableMetadata.b.w(textView3, kVar2, oTConfiguration3);
        com.google.android.gms.cloudmessaging.k kVar3 = (com.google.android.gms.cloudmessaging.k) ((androidx.navigation.internal.m) this.y1.f).d;
        assistantMode.utils.studiableMetadata.b bVar4 = this.B1;
        TextView textView4 = this.v;
        OTConfiguration oTConfiguration4 = this.z1;
        bVar4.getClass();
        assistantMode.utils.studiableMetadata.b.w(textView4, kVar3, oTConfiguration4);
        assistantMode.utils.studiableMetadata.b bVar5 = this.B1;
        TextView textView5 = this.w;
        OTConfiguration oTConfiguration5 = this.z1;
        bVar5.getClass();
        assistantMode.utils.studiableMetadata.b.w(textView5, kVar3, oTConfiguration5);
        assistantMode.utils.studiableMetadata.b bVar6 = this.B1;
        TextView textView6 = this.x;
        OTConfiguration oTConfiguration6 = this.z1;
        bVar6.getClass();
        assistantMode.utils.studiableMetadata.b.w(textView6, kVar3, oTConfiguration6);
        assistantMode.utils.studiableMetadata.b bVar7 = this.B1;
        TextView textView7 = this.z;
        OTConfiguration oTConfiguration7 = this.z1;
        bVar7.getClass();
        assistantMode.utils.studiableMetadata.b.w(textView7, kVar3, oTConfiguration7);
        assistantMode.utils.studiableMetadata.b bVar8 = this.B1;
        TextView textView8 = this.B;
        OTConfiguration oTConfiguration8 = this.z1;
        bVar8.getClass();
        assistantMode.utils.studiableMetadata.b.w(textView8, kVar3, oTConfiguration8);
        assistantMode.utils.studiableMetadata.b bVar9 = this.B1;
        TextView textView9 = this.C;
        OTConfiguration oTConfiguration9 = this.z1;
        bVar9.getClass();
        assistantMode.utils.studiableMetadata.b.w(textView9, kVar3, oTConfiguration9);
        assistantMode.utils.studiableMetadata.b bVar10 = this.B1;
        TextView textView10 = this.A;
        OTConfiguration oTConfiguration10 = this.z1;
        bVar10.getClass();
        assistantMode.utils.studiableMetadata.b.w(textView10, kVar3, oTConfiguration10);
        assistantMode.utils.studiableMetadata.b bVar11 = this.B1;
        TextView textView11 = this.G;
        OTConfiguration oTConfiguration11 = this.z1;
        bVar11.getClass();
        assistantMode.utils.studiableMetadata.b.w(textView11, kVar3, oTConfiguration11);
        assistantMode.utils.studiableMetadata.b bVar12 = this.B1;
        TextView textView12 = this.J;
        OTConfiguration oTConfiguration12 = this.z1;
        bVar12.getClass();
        assistantMode.utils.studiableMetadata.b.w(textView12, kVar3, oTConfiguration12);
        assistantMode.utils.studiableMetadata.b bVar13 = this.B1;
        TextView textView13 = this.K;
        OTConfiguration oTConfiguration13 = this.z1;
        bVar13.getClass();
        assistantMode.utils.studiableMetadata.b.w(textView13, kVar3, oTConfiguration13);
        com.google.android.gms.cloudmessaging.k kVar4 = (com.google.android.gms.cloudmessaging.k) ((androidx.navigation.internal.m) this.y1.g).d;
        assistantMode.utils.studiableMetadata.b bVar14 = this.B1;
        TextView textView14 = this.H;
        OTConfiguration oTConfiguration14 = this.z1;
        bVar14.getClass();
        assistantMode.utils.studiableMetadata.b.w(textView14, kVar4, oTConfiguration14);
        assistantMode.utils.studiableMetadata.b bVar15 = this.B1;
        TextView textView15 = this.I;
        OTConfiguration oTConfiguration15 = this.z1;
        bVar15.getClass();
        assistantMode.utils.studiableMetadata.b.w(textView15, kVar4, oTConfiguration15);
        assistantMode.utils.studiableMetadata.b bVar16 = this.B1;
        TextView textView16 = this.y;
        OTConfiguration oTConfiguration16 = this.z1;
        bVar16.getClass();
        assistantMode.utils.studiableMetadata.b.w(textView16, kVar4, oTConfiguration16);
        com.google.android.gms.cloudmessaging.k kVar5 = (com.google.android.gms.cloudmessaging.k) ((androidx.navigation.internal.m) this.y1.h).d;
        assistantMode.utils.studiableMetadata.b bVar17 = this.B1;
        TextView textView17 = this.E;
        OTConfiguration oTConfiguration17 = this.z1;
        bVar17.getClass();
        assistantMode.utils.studiableMetadata.b.w(textView17, kVar5, oTConfiguration17);
        com.google.android.gms.cloudmessaging.k kVar6 = (com.google.android.gms.cloudmessaging.k) ((androidx.navigation.internal.m) this.y1.i).d;
        assistantMode.utils.studiableMetadata.b bVar18 = this.B1;
        TextView textView18 = this.F;
        OTConfiguration oTConfiguration18 = this.z1;
        bVar18.getClass();
        assistantMode.utils.studiableMetadata.b.w(textView18, kVar6, oTConfiguration18);
    }

    public final void X() {
        String str = (String) this.y1.c;
        if (str != null && !com.onetrust.otpublishers.headless.Internal.a.j(str)) {
            this.w1 = (String) this.y1.c;
        }
        String str2 = (String) this.y1.b;
        if (str2 != null && !com.onetrust.otpublishers.headless.Internal.a.j(str2)) {
            this.v1 = (String) this.y1.b;
        }
        String str3 = (String) this.y1.d;
        if (str3 == null || com.onetrust.otpublishers.headless.Internal.a.j(str3)) {
            return;
        }
        this.x1 = (String) this.y1.d;
    }

    public final void a() throws NumberFormatException {
        if (!com.onetrust.otpublishers.headless.Internal.a.j((String) ((com.google.android.gms.cloudmessaging.k) ((androidx.navigation.internal.m) this.y1.e).d).d)) {
            this.s.setTextSize(Float.parseFloat((String) ((com.google.android.gms.cloudmessaging.k) ((androidx.navigation.internal.m) this.y1.e).d).d));
        }
        if (!com.onetrust.otpublishers.headless.Internal.a.j((String) ((com.google.android.gms.cloudmessaging.k) ((androidx.navigation.internal.m) this.y1.h).d).d)) {
            this.E.setTextSize(Float.parseFloat((String) ((com.google.android.gms.cloudmessaging.k) ((androidx.navigation.internal.m) this.y1.h).d).d));
        }
        if (!com.onetrust.otpublishers.headless.Internal.a.j((String) ((com.google.android.gms.cloudmessaging.k) ((androidx.navigation.internal.m) this.y1.i).d).d)) {
            this.F.setTextSize(Float.parseFloat((String) ((com.google.android.gms.cloudmessaging.k) ((androidx.navigation.internal.m) this.y1.i).d).d));
        }
        String str = (String) ((com.google.android.gms.cloudmessaging.k) ((androidx.navigation.internal.m) ((com.quizlet.data.repository.user.e) this.y1.j).b).d).d;
        if (!com.onetrust.otpublishers.headless.Internal.a.j(str)) {
            this.t.setTextSize(Float.parseFloat(str));
            this.u.setTextSize(Float.parseFloat(str));
        }
        if (!com.onetrust.otpublishers.headless.Internal.a.j((String) ((com.google.android.gms.cloudmessaging.k) ((androidx.navigation.internal.m) this.y1.f).d).d)) {
            float f = Float.parseFloat((String) ((com.google.android.gms.cloudmessaging.k) ((androidx.navigation.internal.m) this.y1.f).d).d);
            this.v.setTextSize(f);
            this.w.setTextSize(f);
            this.x.setTextSize(f);
            this.z.setTextSize(f);
            this.B.setTextSize(f);
            this.C.setTextSize(f);
            this.A.setTextSize(f);
            this.G.setTextSize(f);
            this.J.setTextSize(f);
            this.K.setTextSize(f);
        }
        if (com.onetrust.otpublishers.headless.Internal.a.j((String) ((com.google.android.gms.cloudmessaging.k) ((androidx.navigation.internal.m) this.y1.g).d).d)) {
            return;
        }
        float f2 = Float.parseFloat((String) ((com.google.android.gms.cloudmessaging.k) ((androidx.navigation.internal.m) this.y1.g).d).d);
        this.H.setTextSize(f2);
        this.I.setTextSize(f2);
        this.y.setTextSize(f2);
    }

    @Override // android.view.View.OnClickListener
    public final void onClick(View view) {
        int id = view.getId();
        if (id != R.id.vendor_detail_back) {
            if (id == R.id.VD_vendors_privacy_notice) {
                com.onetrust.otpublishers.headless.Internal.a.c(this.X, this.q);
                return;
            } else {
                if (id == R.id.VD_vendors_li_privacy_notice) {
                    com.onetrust.otpublishers.headless.Internal.a.c(this.X, this.r);
                    return;
                }
                return;
            }
        }
        G();
        w wVar = this.q1;
        if (wVar != null) {
            com.google.firebase.perf.logging.b bVar = D.D;
            D this$0 = wVar.a;
            Intrinsics.checkNotNullParameter(this$0, "this$0");
            this$0.X().D();
        }
    }

    @Override // androidx.fragment.app.Fragment, android.content.ComponentCallbacks
    public final void onConfigurationChanged(Configuration configuration) {
        super.onConfigurationChanged(configuration);
        assistantMode.utils.studiableMetadata.b bVar = this.B1;
        androidx.fragment.app.I activity = getActivity();
        com.google.android.material.bottomsheet.h hVar = this.V;
        bVar.getClass();
        assistantMode.utils.studiableMetadata.b.z(activity, hVar);
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, androidx.fragment.app.Fragment
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        setRetainInstance(true);
        if (this.Y == null && getActivity() != null) {
            this.Y = new OTPublishersHeadlessSDK(getActivity());
        }
        androidx.fragment.app.I activity = getActivity();
        if (com.google.mlkit.common.internal.model.a.n(activity, OTFragmentTags.OT_VENDOR_DETAILS_FRAGMENT_TAG)) {
            SharedPreferences sharedPreferencesD = AbstractC3705q4.d(activity);
            String str = OTThemeConstants.NO_SDK_THEME_OVERRIDE;
            String string = sharedPreferencesD.getString("OT_UX_SDK_THEME", OTThemeConstants.NO_SDK_THEME_OVERRIDE);
            if (com.onetrust.otpublishers.headless.Internal.a.j(string)) {
                string = OTThemeConstants.NO_SDK_THEME_OVERRIDE;
            }
            if (!string.equals(OTThemeConstants.OT_SDK_UI_THEME)) {
                String string2 = activity.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOT_SDK_APP_CONFIGURATION", 0).getString("OT_UX_SDK_THEME", OTThemeConstants.NO_SDK_THEME_OVERRIDE);
                if (!com.onetrust.otpublishers.headless.Internal.a.j(string2)) {
                    str = string2;
                }
                if (!str.equals(OTThemeConstants.OT_THEME_APP_COMPACT_LIGHT_NO_ACTION_BAR_LANDSCAPE_FULL_SCREEN)) {
                    return;
                }
            }
            OTLogger.c("OneTrust", 3, "set theme to OT defined theme ");
            M();
        }
    }

    @Override // androidx.fragment.app.Fragment
    public final View onCreateView(LayoutInflater layoutInflater, ViewGroup viewGroup, Bundle bundle) throws JSONException {
        this.X = getContext();
        this.E1 = new com.onetrust.otpublishers.headless.UI.mobiledatautils.b();
        if (!this.E1.j(assistantMode.utils.studiableMetadata.b.d(this.X, this.z1), this.X, this.Y)) {
            G();
            return null;
        }
        Context context = this.X;
        if (com.onetrust.otpublishers.headless.Internal.a.o(context)) {
            layoutInflater = layoutInflater.cloneInContext(new androidx.appcompat.view.d(context, R.style.Theme_AppCompat_Light_NoActionBar));
        }
        View viewInflate = layoutInflater.inflate(R.layout.ot_vendors_details_fragment, viewGroup, false);
        this.s = (TextView) viewInflate.findViewById(R.id.VD_vendor_name);
        this.t = (TextView) viewInflate.findViewById(R.id.VD_vendors_privacy_notice);
        this.u = (TextView) viewInflate.findViewById(R.id.VD_vendors_li_privacy_notice);
        this.l1 = (RelativeLayout) viewInflate.findViewById(R.id.vendor_detail_header);
        this.m1 = (RelativeLayout) viewInflate.findViewById(R.id.vendor_detail_RL);
        this.D = (TextView) viewInflate.findViewById(R.id.VD_page_title);
        this.W = (ImageView) viewInflate.findViewById(R.id.vendor_detail_back);
        this.c1 = (SwitchCompat) viewInflate.findViewById(R.id.VD_consent_switch);
        this.d1 = (SwitchCompat) viewInflate.findViewById(R.id.VD_LI_switch);
        this.n1 = (LinearLayout) viewInflate.findViewById(R.id.vd_linearLyt);
        this.E = (TextView) viewInflate.findViewById(R.id.VD_consent_title);
        this.F = (TextView) viewInflate.findViewById(R.id.VD_LISwitch_title);
        this.r1 = viewInflate.findViewById(R.id.name_view);
        this.s1 = viewInflate.findViewById(R.id.consent_title_view);
        this.e1 = (RecyclerView) viewInflate.findViewById(R.id.vd_purpose_rv);
        this.f1 = (RecyclerView) viewInflate.findViewById(R.id.vd_declaration_rv);
        this.g1 = (RecyclerView) viewInflate.findViewById(R.id.vd_liPurpose_rv);
        this.h1 = (RecyclerView) viewInflate.findViewById(R.id.vd_feature_rv);
        this.i1 = (RecyclerView) viewInflate.findViewById(R.id.vd_spFeature_rv);
        this.j1 = (RecyclerView) viewInflate.findViewById(R.id.vd_SpPurpose_rv);
        this.v = (TextView) viewInflate.findViewById(R.id.VD_purpose_title);
        this.w = (TextView) viewInflate.findViewById(R.id.VD_declaration_title);
        this.x = (TextView) viewInflate.findViewById(R.id.VD_retention_title);
        this.y = (TextView) viewInflate.findViewById(R.id.VD_standard_retention_title);
        this.z = (TextView) viewInflate.findViewById(R.id.VD_LIPurpose_title);
        this.A = (TextView) viewInflate.findViewById(R.id.VD_Feature_title);
        this.C = (TextView) viewInflate.findViewById(R.id.VD_SpFeature_title);
        this.B = (TextView) viewInflate.findViewById(R.id.VD_SpPurpose_title);
        this.G = (TextView) viewInflate.findViewById(R.id.VD_lifespan_label);
        this.H = (TextView) viewInflate.findViewById(R.id.VD_lifespan_value);
        this.I = (TextView) viewInflate.findViewById(R.id.VD_lifespan_desc);
        this.M = (RelativeLayout) viewInflate.findViewById(R.id.disclosure_RL);
        this.J = (TextView) viewInflate.findViewById(R.id.VD_disclosure_title);
        this.k1 = (RecyclerView) viewInflate.findViewById(R.id.VD_disclosure_rv);
        this.o1 = (LinearLayout) viewInflate.findViewById(R.id.scrollable_content);
        this.D1 = (TextView) viewInflate.findViewById(R.id.view_powered_by_logo);
        this.K = (TextView) viewInflate.findViewById(R.id.VD_domain_used_title);
        this.L = (RecyclerView) viewInflate.findViewById(R.id.VD_domains_rv);
        com.google.mlkit.common.internal.model.a.f(this.X, viewInflate, "VendorDetail");
        this.B1 = new assistantMode.utils.studiableMetadata.b(22);
        this.t.setOnClickListener(this);
        this.u.setOnClickListener(this);
        this.W.setOnClickListener(this);
        final int i = 0;
        this.c1.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener(this) { // from class: com.onetrust.otpublishers.headless.UI.fragment.G
            public final /* synthetic */ I b;

            {
                this.b = this;
            }

            @Override // android.widget.CompoundButton.OnCheckedChangeListener
            public final void onCheckedChanged(CompoundButton compoundButton, boolean z) {
                assistantMode.utils.studiableMetadata.b bVar;
                Context context2;
                SwitchCompat switchCompat;
                String str;
                String str2;
                assistantMode.utils.studiableMetadata.b bVar2;
                Context context3;
                SwitchCompat switchCompat2;
                String str3;
                String str4;
                switch (i) {
                    case 0:
                        I i2 = this.b;
                        i2.Y.updateVendorConsent(OTVendorListMode.IAB, i2.p1, z);
                        if (z) {
                            bVar = i2.B1;
                            context2 = i2.X;
                            switchCompat = i2.c1;
                            str = i2.x1;
                            str2 = i2.v1;
                        } else {
                            bVar = i2.B1;
                            context2 = i2.X;
                            switchCompat = i2.c1;
                            str = i2.x1;
                            str2 = i2.w1;
                        }
                        bVar.getClass();
                        assistantMode.utils.studiableMetadata.b.s(context2, switchCompat, str, str2);
                        break;
                    default:
                        I i3 = this.b;
                        i3.Y.updateVendorLegitInterest(OTVendorListMode.IAB, i3.p1, z);
                        if (z) {
                            bVar2 = i3.B1;
                            context3 = i3.X;
                            switchCompat2 = i3.d1;
                            str3 = i3.x1;
                            str4 = i3.v1;
                        } else {
                            bVar2 = i3.B1;
                            context3 = i3.X;
                            switchCompat2 = i3.d1;
                            str3 = i3.x1;
                            str4 = i3.w1;
                        }
                        bVar2.getClass();
                        assistantMode.utils.studiableMetadata.b.s(context3, switchCompat2, str3, str4);
                        break;
                }
            }
        });
        final int i2 = 1;
        this.d1.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener(this) { // from class: com.onetrust.otpublishers.headless.UI.fragment.G
            public final /* synthetic */ I b;

            {
                this.b = this;
            }

            @Override // android.widget.CompoundButton.OnCheckedChangeListener
            public final void onCheckedChanged(CompoundButton compoundButton, boolean z) {
                assistantMode.utils.studiableMetadata.b bVar;
                Context context2;
                SwitchCompat switchCompat;
                String str;
                String str2;
                assistantMode.utils.studiableMetadata.b bVar2;
                Context context3;
                SwitchCompat switchCompat2;
                String str3;
                String str4;
                switch (i2) {
                    case 0:
                        I i22 = this.b;
                        i22.Y.updateVendorConsent(OTVendorListMode.IAB, i22.p1, z);
                        if (z) {
                            bVar = i22.B1;
                            context2 = i22.X;
                            switchCompat = i22.c1;
                            str = i22.x1;
                            str2 = i22.v1;
                        } else {
                            bVar = i22.B1;
                            context2 = i22.X;
                            switchCompat = i22.c1;
                            str = i22.x1;
                            str2 = i22.w1;
                        }
                        bVar.getClass();
                        assistantMode.utils.studiableMetadata.b.s(context2, switchCompat, str, str2);
                        break;
                    default:
                        I i3 = this.b;
                        i3.Y.updateVendorLegitInterest(OTVendorListMode.IAB, i3.p1, z);
                        if (z) {
                            bVar2 = i3.B1;
                            context3 = i3.X;
                            switchCompat2 = i3.d1;
                            str3 = i3.x1;
                            str4 = i3.v1;
                        } else {
                            bVar2 = i3.B1;
                            context3 = i3.X;
                            switchCompat2 = i3.d1;
                            str3 = i3.x1;
                            str4 = i3.w1;
                        }
                        bVar2.getClass();
                        assistantMode.utils.studiableMetadata.b.s(context3, switchCompat2, str3, str4);
                        break;
                }
            }
        });
        final int i3 = 0;
        this.c1.setOnClickListener(new View.OnClickListener(this) { // from class: com.onetrust.otpublishers.headless.UI.fragment.H
            public final /* synthetic */ I b;

            {
                this.b = this;
            }

            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                switch (i3) {
                    case 0:
                        I i4 = this.b;
                        androidx.compose.foundation.lazy.grid.m mVar = new androidx.compose.foundation.lazy.grid.m(15, 4);
                        mVar.c = i4.p1;
                        mVar.b = i4.c1.isChecked() ? 1 : 0;
                        com.onetrust.otpublishers.headless.Internal.Event.a aVar = i4.C1;
                        if (aVar != null) {
                            aVar.a(mVar);
                        } else {
                            OTLogger.c("OneTrust", 6, "Error on sending UI events, listener set was found to be null.This could be because the activity has been recreated. \n Please set listener to get UI event callbacks.");
                        }
                        mVar.e = OTVendorListMode.IAB;
                        com.onetrust.otpublishers.headless.Internal.Event.a aVar2 = i4.C1;
                        if (aVar2 == null) {
                            OTLogger.c("OneTrust", 6, "Error on sending UI events, listener set was found to be null.This could be because the activity has been recreated. \n Please set listener to get UI event callbacks.");
                            break;
                        } else {
                            aVar2.a(mVar);
                            break;
                        }
                    default:
                        I i5 = this.b;
                        androidx.compose.foundation.lazy.grid.m mVar2 = new androidx.compose.foundation.lazy.grid.m(16, 4);
                        mVar2.c = i5.p1;
                        mVar2.b = i5.d1.isChecked() ? 1 : 0;
                        com.onetrust.otpublishers.headless.Internal.Event.a aVar3 = i5.C1;
                        if (aVar3 == null) {
                            OTLogger.c("OneTrust", 6, "Error on sending UI events, listener set was found to be null.This could be because the activity has been recreated. \n Please set listener to get UI event callbacks.");
                            break;
                        } else {
                            aVar3.a(mVar2);
                            break;
                        }
                }
            }
        });
        final int i4 = 1;
        this.d1.setOnClickListener(new View.OnClickListener(this) { // from class: com.onetrust.otpublishers.headless.UI.fragment.H
            public final /* synthetic */ I b;

            {
                this.b = this;
            }

            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                switch (i4) {
                    case 0:
                        I i42 = this.b;
                        androidx.compose.foundation.lazy.grid.m mVar = new androidx.compose.foundation.lazy.grid.m(15, 4);
                        mVar.c = i42.p1;
                        mVar.b = i42.c1.isChecked() ? 1 : 0;
                        com.onetrust.otpublishers.headless.Internal.Event.a aVar = i42.C1;
                        if (aVar != null) {
                            aVar.a(mVar);
                        } else {
                            OTLogger.c("OneTrust", 6, "Error on sending UI events, listener set was found to be null.This could be because the activity has been recreated. \n Please set listener to get UI event callbacks.");
                        }
                        mVar.e = OTVendorListMode.IAB;
                        com.onetrust.otpublishers.headless.Internal.Event.a aVar2 = i42.C1;
                        if (aVar2 == null) {
                            OTLogger.c("OneTrust", 6, "Error on sending UI events, listener set was found to be null.This could be because the activity has been recreated. \n Please set listener to get UI event callbacks.");
                            break;
                        } else {
                            aVar2.a(mVar);
                            break;
                        }
                    default:
                        I i5 = this.b;
                        androidx.compose.foundation.lazy.grid.m mVar2 = new androidx.compose.foundation.lazy.grid.m(16, 4);
                        mVar2.c = i5.p1;
                        mVar2.b = i5.d1.isChecked() ? 1 : 0;
                        com.onetrust.otpublishers.headless.Internal.Event.a aVar3 = i5.C1;
                        if (aVar3 == null) {
                            OTLogger.c("OneTrust", 6, "Error on sending UI events, listener set was found to be null.This could be because the activity has been recreated. \n Please set listener to get UI event callbacks.");
                            break;
                        } else {
                            aVar3.a(mVar2);
                            break;
                        }
                }
            }
        });
        try {
            JSONObject preferenceCenterData = this.Y.getPreferenceCenterData();
            T(preferenceCenterData);
            String strOptString = preferenceCenterData.optString("BConsentText");
            this.E.setText(strOptString);
            this.c1.setContentDescription(strOptString);
            String strOptString2 = preferenceCenterData.optString("BLegitInterestText");
            this.F.setText(strOptString2);
            this.d1.setContentDescription(strOptString2);
            if (preferenceCenterData.has("PCenterViewPrivacyPolicyText")) {
                this.t.setText(preferenceCenterData.getString("PCenterViewPrivacyPolicyText"));
                if (preferenceCenterData.has("PCPrivacyLinkActionAriaLabel")) {
                    com.google.mlkit.common.internal.model.a.k(this.t, preferenceCenterData.optString("PCPrivacyLinkActionAriaLabel"));
                }
            }
            if (preferenceCenterData.has("PCIABVendorLegIntClaimText")) {
                this.u.setText(preferenceCenterData.getString("PCIABVendorLegIntClaimText"));
                if (preferenceCenterData.has("PCPrivacyLinkActionAriaLabel")) {
                    com.google.mlkit.common.internal.model.a.k(this.u, preferenceCenterData.optString("PCPrivacyLinkActionAriaLabel"));
                }
            }
            if (preferenceCenterData.has("PCenterBackText")) {
                this.W.setContentDescription(preferenceCenterData.optString("PCenterBackText"));
            }
            if (getArguments() != null) {
                String string = getArguments().getString("vendorId");
                this.p1 = string;
                JSONObject vendorDetails = this.Y.getVendorDetails(OTVendorListMode.IAB, string);
                this.Z = vendorDetails;
                if (vendorDetails != null) {
                    String string2 = vendorDetails.getString("name");
                    JSONObject jSONObjectOptJSONObject = this.Z.optJSONObject("dataRetention");
                    this.s.setText(string2);
                    V.p(this.s, true);
                    if (com.google.mlkit.common.internal.model.a.m(this.X)) {
                        com.google.mlkit.common.internal.model.a.h(this.X, string2, this.n1, R.id.VD_consent_switch);
                        com.google.mlkit.common.internal.model.a.h(this.X, string2, this.n1, R.id.VD_LI_switch);
                    }
                    String str = this.E1.M;
                    JSONObject jSONObject = this.Z;
                    String strB = com.onetrust.otpublishers.headless.Internal.a.l(str) ? com.onetrust.otpublishers.headless.UI.TVUI.datautils.e.b(preferenceCenterData, jSONObject, false) : jSONObject.optString("policyUrl");
                    this.q = strB;
                    if (com.onetrust.otpublishers.headless.Internal.a.j(strB)) {
                        this.t.setVisibility(8);
                    }
                    String strB2 = com.onetrust.otpublishers.headless.Internal.a.l(this.E1.M) ? com.onetrust.otpublishers.headless.UI.TVUI.datautils.e.b(preferenceCenterData, this.Z, true) : "";
                    this.r = strB2;
                    if (!com.onetrust.otpublishers.headless.Internal.a.j(strB2)) {
                        this.u.setVisibility(0);
                    }
                    this.G.setText(preferenceCenterData.optString("PCenterVendorListLifespan") + ":");
                    this.I.setText(preferenceCenterData.optString("PCenterVendorListNonCookieUsage"));
                    this.H.setText(assistantMode.utils.studiableMetadata.b.k(this.Z.optLong("cookieMaxAgeSeconds"), preferenceCenterData));
                    V(preferenceCenterData);
                    R(preferenceCenterData, jSONObjectOptJSONObject);
                    U(jSONObjectOptJSONObject, preferenceCenterData);
                }
            }
            this.E1.c(this.D1, this.z1);
            return viewInflate;
        } catch (Exception e) {
            Z.n("error while populating Vendor Detail fields", e, "VendorDetail", 6);
            return viewInflate;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:15:0x0058  */
    /* JADX WARN: Removed duplicated region for block: B:19:0x007a A[Catch: Exception -> 0x002f, TryCatch #0 {Exception -> 0x002f, blocks: (B:5:0x0009, B:8:0x001f, B:16:0x005a, B:18:0x006a, B:20:0x0089, B:19:0x007a, B:11:0x0031, B:13:0x0050, B:12:0x0041), top: B:24:0x0009 }] */
    @Override // androidx.fragment.app.Fragment
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void onResume() throws org.json.JSONException {
        /*
            r9 = this;
            super.onResume()
            org.json.JSONObject r0 = r9.Z
            if (r0 != 0) goto L9
            goto L98
        L9:
            java.lang.String r1 = "consent"
            int r0 = r0.getInt(r1)     // Catch: java.lang.Exception -> L2f
            org.json.JSONObject r1 = r9.Z     // Catch: java.lang.Exception -> L2f
            java.lang.String r2 = "legIntStatus"
            int r1 = r1.getInt(r2)     // Catch: java.lang.Exception -> L2f
            r2 = 0
            r3 = 1
            r4 = 8
            if (r0 == 0) goto L41
            if (r0 == r3) goto L31
            androidx.appcompat.widget.SwitchCompat r0 = r9.c1     // Catch: java.lang.Exception -> L2f
            r0.setVisibility(r4)     // Catch: java.lang.Exception -> L2f
            android.widget.TextView r0 = r9.E     // Catch: java.lang.Exception -> L2f
            r0.setVisibility(r4)     // Catch: java.lang.Exception -> L2f
            android.view.View r0 = r9.r1     // Catch: java.lang.Exception -> L2f
            r0.setVisibility(r4)     // Catch: java.lang.Exception -> L2f
            goto L56
        L2f:
            r0 = move-exception
            goto L90
        L31:
            androidx.appcompat.widget.SwitchCompat r0 = r9.c1     // Catch: java.lang.Exception -> L2f
            r0.setChecked(r3)     // Catch: java.lang.Exception -> L2f
            assistantMode.utils.studiableMetadata.b r0 = r9.B1     // Catch: java.lang.Exception -> L2f
            android.content.Context r5 = r9.X     // Catch: java.lang.Exception -> L2f
            androidx.appcompat.widget.SwitchCompat r6 = r9.c1     // Catch: java.lang.Exception -> L2f
            java.lang.String r7 = r9.x1     // Catch: java.lang.Exception -> L2f
            java.lang.String r8 = r9.v1     // Catch: java.lang.Exception -> L2f
            goto L50
        L41:
            androidx.appcompat.widget.SwitchCompat r0 = r9.c1     // Catch: java.lang.Exception -> L2f
            r0.setChecked(r2)     // Catch: java.lang.Exception -> L2f
            assistantMode.utils.studiableMetadata.b r0 = r9.B1     // Catch: java.lang.Exception -> L2f
            android.content.Context r5 = r9.X     // Catch: java.lang.Exception -> L2f
            androidx.appcompat.widget.SwitchCompat r6 = r9.c1     // Catch: java.lang.Exception -> L2f
            java.lang.String r7 = r9.x1     // Catch: java.lang.Exception -> L2f
            java.lang.String r8 = r9.w1     // Catch: java.lang.Exception -> L2f
        L50:
            r0.getClass()     // Catch: java.lang.Exception -> L2f
            assistantMode.utils.studiableMetadata.b.s(r5, r6, r7, r8)     // Catch: java.lang.Exception -> L2f
        L56:
            if (r1 == 0) goto L7a
            if (r1 == r3) goto L6a
            androidx.appcompat.widget.SwitchCompat r0 = r9.d1     // Catch: java.lang.Exception -> L2f
            r0.setVisibility(r4)     // Catch: java.lang.Exception -> L2f
            android.widget.TextView r0 = r9.F     // Catch: java.lang.Exception -> L2f
            r0.setVisibility(r4)     // Catch: java.lang.Exception -> L2f
            android.view.View r0 = r9.s1     // Catch: java.lang.Exception -> L2f
            r0.setVisibility(r4)     // Catch: java.lang.Exception -> L2f
            return
        L6a:
            androidx.appcompat.widget.SwitchCompat r0 = r9.d1     // Catch: java.lang.Exception -> L2f
            r0.setChecked(r3)     // Catch: java.lang.Exception -> L2f
            assistantMode.utils.studiableMetadata.b r0 = r9.B1     // Catch: java.lang.Exception -> L2f
            android.content.Context r1 = r9.X     // Catch: java.lang.Exception -> L2f
            androidx.appcompat.widget.SwitchCompat r2 = r9.d1     // Catch: java.lang.Exception -> L2f
            java.lang.String r3 = r9.x1     // Catch: java.lang.Exception -> L2f
            java.lang.String r4 = r9.v1     // Catch: java.lang.Exception -> L2f
            goto L89
        L7a:
            androidx.appcompat.widget.SwitchCompat r0 = r9.d1     // Catch: java.lang.Exception -> L2f
            r0.setChecked(r2)     // Catch: java.lang.Exception -> L2f
            assistantMode.utils.studiableMetadata.b r0 = r9.B1     // Catch: java.lang.Exception -> L2f
            android.content.Context r1 = r9.X     // Catch: java.lang.Exception -> L2f
            androidx.appcompat.widget.SwitchCompat r2 = r9.d1     // Catch: java.lang.Exception -> L2f
            java.lang.String r3 = r9.x1     // Catch: java.lang.Exception -> L2f
            java.lang.String r4 = r9.w1     // Catch: java.lang.Exception -> L2f
        L89:
            r0.getClass()     // Catch: java.lang.Exception -> L2f
            assistantMode.utils.studiableMetadata.b.s(r1, r2, r3, r4)     // Catch: java.lang.Exception -> L2f
            return
        L90:
            java.lang.String r1 = "error while setting toggle values"
            java.lang.String r2 = "VendorDetail"
            r3 = 6
            com.google.android.gms.measurement.internal.Z.n(r1, r0, r2, r3)
        L98:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.UI.fragment.I.onResume():void");
    }

    public final void a(JSONObject jSONObject) {
        androidx.navigation.internal.m mVar = (androidx.navigation.internal.m) this.y1.e;
        this.u1 = !com.onetrust.otpublishers.headless.Internal.a.j((String) mVar.b) ? (String) mVar.b : jSONObject.optString("PcTextColor");
        androidx.navigation.internal.m mVar2 = (androidx.navigation.internal.m) this.y1.g;
        this.t1 = !com.onetrust.otpublishers.headless.Internal.a.j((String) mVar2.b) ? (String) mVar2.b : jSONObject.optString("PcTextColor");
    }
}

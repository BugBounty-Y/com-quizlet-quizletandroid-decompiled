package com.onetrust.otpublishers.headless.UI.fragment;

import android.app.Dialog;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.res.Configuration;
import android.graphics.Color;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.core.view.V;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.google.android.gms.internal.ads.C3;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3705q4;
import com.google.android.gms.measurement.internal.Z;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.onetrust.otpublishers.headless.Public.DataModel.OTConfiguration;
import com.onetrust.otpublishers.headless.Public.Keys.OTFragmentTags;
import com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK;
import com.onetrust.otpublishers.headless.Public.OTThemeConstants;
import com.onetrust.otpublishers.headless.UI.adapter.C4048d;
import com.quizlet.quizletandroid.R;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* renamed from: com.onetrust.otpublishers.headless.UI.fragment.i, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public class ViewOnClickListenerC4065i extends com.google.android.material.bottomsheet.i implements View.OnClickListener {
    public C3 A;
    public OTConfiguration B;
    public assistantMode.utils.studiableMetadata.b C;
    public String D;
    public com.onetrust.otpublishers.headless.UI.mobiledatautils.b E;
    public JSONObject F;
    public TextView q;
    public TextView r;
    public RecyclerView s;
    public com.google.android.material.bottomsheet.h t;
    public ImageView u;
    public Context v;
    public OTPublishersHeadlessSDK w;
    public RelativeLayout x;
    public RelativeLayout y;
    public LinearLayout z;

    @Override // com.google.android.material.bottomsheet.i, androidx.appcompat.app.E, androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t
    public final Dialog K(Bundle bundle) {
        Dialog dialogK = super.K(bundle);
        dialogK.setOnShowListener(new com.onetrust.otpublishers.headless.UI.TVUI.fragments.e(this, 4));
        return dialogK;
    }

    public final void Q(JSONObject jSONObject) throws NumberFormatException {
        try {
            int iD = assistantMode.utils.studiableMetadata.b.d(this.v, this.B);
            C3 c3F = new com.onetrust.otpublishers.headless.UI.UIProperty.f(this.v, iD).f();
            this.A = c3F;
            String str = (String) ((androidx.navigation.internal.m) c3F.g).b;
            String strOptString = jSONObject.optString("PcTextColor");
            String str2 = "#696969";
            if (com.onetrust.otpublishers.headless.Internal.a.j(str)) {
                str = !com.onetrust.otpublishers.headless.Internal.a.j(strOptString) ? strOptString : iD == 11 ? "#FFFFFF" : "#696969";
            }
            this.D = str;
            String str3 = (String) this.A.a;
            String strOptString2 = jSONObject.optString("PcBackgroundColor");
            if (com.onetrust.otpublishers.headless.Internal.a.j(str3)) {
                str3 = !com.onetrust.otpublishers.headless.Internal.a.j(strOptString2) ? strOptString2 : iD == 11 ? "#2F2F2F" : "#FFFFFF";
            }
            String str4 = (String) this.A.k;
            String strOptString3 = jSONObject.optString("PcTextColor");
            if (!com.onetrust.otpublishers.headless.Internal.a.j(str4)) {
                str2 = str4;
            } else if (!com.onetrust.otpublishers.headless.Internal.a.j(strOptString3)) {
                str2 = strOptString3;
            } else if (iD == 11) {
                str2 = "#FFFFFF";
            }
            this.y.setBackgroundColor(Color.parseColor(str3));
            this.x.setBackgroundColor(Color.parseColor(str3));
            this.z.setBackgroundColor(Color.parseColor(str3));
            this.u.setColorFilter(Color.parseColor(str2));
            com.onetrust.otpublishers.headless.UI.mobiledatautils.b bVar = this.E;
            com.onetrust.otpublishers.headless.UI.Helper.c cVar = bVar.a;
            com.onetrust.otpublishers.headless.UI.Helper.c cVar2 = bVar.x;
            TextView textView = this.q;
            textView.setTextColor(Color.parseColor(cVar.b()));
            assistantMode.utils.studiableMetadata.b.x(textView, cVar.q);
            if (!com.onetrust.otpublishers.headless.Internal.a.j(cVar.r)) {
                textView.setTextSize(Float.parseFloat(cVar.r));
            }
            assistantMode.utils.studiableMetadata.b bVar2 = this.C;
            com.google.android.gms.cloudmessaging.k kVar = (com.google.android.gms.cloudmessaging.k) cVar.d;
            OTConfiguration oTConfiguration = this.B;
            bVar2.getClass();
            assistantMode.utils.studiableMetadata.b.w(textView, kVar, oTConfiguration);
            TextView textView2 = this.r;
            textView2.setTextColor(Color.parseColor(cVar2.b()));
            assistantMode.utils.studiableMetadata.b.x(textView2, cVar2.q);
            if (!com.onetrust.otpublishers.headless.Internal.a.j(cVar2.r)) {
                textView2.setTextSize(Float.parseFloat(cVar2.r));
            }
            assistantMode.utils.studiableMetadata.b bVar3 = this.C;
            com.google.android.gms.cloudmessaging.k kVar2 = (com.google.android.gms.cloudmessaging.k) cVar2.d;
            OTConfiguration oTConfiguration2 = this.B;
            bVar3.getClass();
            assistantMode.utils.studiableMetadata.b.w(textView2, kVar2, oTConfiguration2);
        } catch (JSONException e) {
            Z.p("Error while applying styles to Vendor details, err : ", e, "OneTrust", 6);
        }
    }

    public final void a(JSONObject jSONObject) {
        this.C.getClass();
        String strOptString = jSONObject.optString("GroupNameMobile");
        if (com.onetrust.otpublishers.headless.Internal.a.j(strOptString)) {
            strOptString = jSONObject.optString("GroupName");
        }
        this.q.setText(this.E.N);
        V.p(this.q, true);
        this.r.setText(strOptString);
        V.p(this.r, true);
        JSONArray jSONArray = jSONObject.has("IabIllustrations") ? jSONObject.getJSONArray("IabIllustrations") : null;
        if (retrofit2.adapter.rxjava3.d.l(jSONArray) && com.onetrust.otpublishers.headless.Internal.a.j("") && !this.E.u.i) {
            return;
        }
        if (jSONArray == null) {
            jSONArray = new JSONArray();
        }
        JSONArray jSONArray2 = jSONArray;
        this.s.setLayoutManager(new LinearLayoutManager(this.v));
        RecyclerView recyclerView = this.s;
        Context context = this.v;
        String str = this.D;
        C3 c3 = this.A;
        recyclerView.setAdapter(new C4048d(context, jSONArray2, str, c3, this.B, c3, this.E));
    }

    @Override // android.view.View.OnClickListener
    public final void onClick(View view) {
        if (view.getId() == R.id.iab_illustration_detail_back) {
            G();
        }
    }

    @Override // androidx.fragment.app.Fragment, android.content.ComponentCallbacks
    public final void onConfigurationChanged(Configuration configuration) {
        super.onConfigurationChanged(configuration);
        assistantMode.utils.studiableMetadata.b bVar = this.C;
        androidx.fragment.app.I activity = getActivity();
        com.google.android.material.bottomsheet.h hVar = this.t;
        bVar.getClass();
        assistantMode.utils.studiableMetadata.b.z(activity, hVar);
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, androidx.fragment.app.Fragment
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        setRetainInstance(true);
        if (this.w == null) {
            G();
        }
        androidx.fragment.app.I activity = getActivity();
        if (com.google.mlkit.common.internal.model.a.n(activity, OTFragmentTags.OT_IAB_ILLUSTRATION_DETAILS_TAG)) {
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
    public final View onCreateView(LayoutInflater layoutInflater, ViewGroup viewGroup, Bundle bundle) {
        this.v = getContext();
        this.E = new com.onetrust.otpublishers.headless.UI.mobiledatautils.b();
        int iD = assistantMode.utils.studiableMetadata.b.d(this.v, this.B);
        if (!this.E.j(iD, this.v, this.w) || this.F == null) {
            G();
            return null;
        }
        Context context = this.v;
        if (com.onetrust.otpublishers.headless.Internal.a.o(context)) {
            layoutInflater = layoutInflater.cloneInContext(new androidx.appcompat.view.d(context, R.style.Theme_AppCompat_Light_NoActionBar));
        }
        View viewInflate = layoutInflater.inflate(R.layout.ot_iab_illustrations_details_fragment, viewGroup, false);
        this.q = (TextView) viewInflate.findViewById(R.id.iab_illustration_title);
        this.r = (TextView) viewInflate.findViewById(R.id.iab_group_name);
        this.x = (RelativeLayout) viewInflate.findViewById(R.id.iab_illustration_detail_header);
        this.y = (RelativeLayout) viewInflate.findViewById(R.id.iab_illustration_detail_RL);
        this.u = (ImageView) viewInflate.findViewById(R.id.iab_illustration_detail_back);
        this.z = (LinearLayout) viewInflate.findViewById(R.id.iab_illustration_linearLyt);
        this.s = (RecyclerView) viewInflate.findViewById(R.id.iab_illustration_details_list);
        com.google.mlkit.common.internal.model.a.f(this.v, viewInflate, "IabIllustrations");
        this.C = new assistantMode.utils.studiableMetadata.b(22);
        try {
            JSONObject preferenceCenterData = this.w.getPreferenceCenterData();
            if (preferenceCenterData != null) {
                Q(preferenceCenterData);
                a(this.F);
                if (preferenceCenterData.has("PCenterBackText")) {
                    this.u.setContentDescription(preferenceCenterData.optString("PCenterBackText"));
                }
            }
        } catch (Exception e) {
            Z.n("error while populating Vendor Detail fields", e, "IabIllustrations", 6);
        }
        this.u.setOnClickListener(this);
        return viewInflate;
    }
}

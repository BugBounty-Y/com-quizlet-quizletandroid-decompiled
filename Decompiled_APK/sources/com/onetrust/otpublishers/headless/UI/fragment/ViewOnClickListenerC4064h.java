package com.onetrust.otpublishers.headless.UI.fragment;

import android.app.Dialog;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.res.Configuration;
import android.content.res.Resources;
import android.graphics.Color;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.appcompat.widget.SwitchCompat;
import androidx.core.view.V;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.google.android.gms.internal.ads.C3;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3605e0;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3705q4;
import com.google.android.gms.measurement.internal.Z;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.onetrust.otpublishers.headless.Public.DataModel.OTConfiguration;
import com.onetrust.otpublishers.headless.Public.Keys.OTFragmentTags;
import com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK;
import com.onetrust.otpublishers.headless.Public.OTThemeConstants;
import com.onetrust.otpublishers.headless.Public.OTVendorListMode;
import com.onetrust.otpublishers.headless.Public.uiutils.OTVendorUtils;
import com.onetrust.otpublishers.headless.UI.adapter.C4046b;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* renamed from: com.onetrust.otpublishers.headless.UI.fragment.h, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public class ViewOnClickListenerC4064h extends com.google.android.material.bottomsheet.i implements View.OnClickListener {
    public SwitchCompat A;
    public RelativeLayout B;
    public RelativeLayout C;
    public LinearLayout D;
    public String E;
    public w F;
    public View G;
    public String H;
    public String I;
    public String J;
    public String K;
    public C3 L;
    public OTConfiguration M;
    public androidx.room.s V;
    public assistantMode.utils.studiableMetadata.b W;
    public String X;
    public String Y;
    public com.onetrust.otpublishers.headless.Internal.Event.a Z;
    public com.onetrust.otpublishers.headless.UI.mobiledatautils.b c1;
    public String q;
    public TextView r;
    public TextView s;
    public TextView t;
    public RecyclerView u;
    public com.google.android.material.bottomsheet.h v;
    public ImageView w;
    public Context x;
    public OTPublishersHeadlessSDK y;
    public JSONObject z;

    @Override // com.google.android.material.bottomsheet.i, androidx.appcompat.app.E, androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t
    public final Dialog K(Bundle bundle) {
        Dialog dialogK = super.K(bundle);
        dialogK.setOnShowListener(new com.onetrust.otpublishers.headless.UI.TVUI.fragments.e(this, 3));
        return dialogK;
    }

    public final void Q(SwitchCompat switchCompat) {
        if (this.K != null) {
            switchCompat.getTrackDrawable().setTint(Color.parseColor(this.K));
        } else {
            switchCompat.getTrackDrawable().setTint(this.x.getColor(R.color.light_greyOT));
        }
        String str = this.I;
        Drawable thumbDrawable = switchCompat.getThumbDrawable();
        if (str != null) {
            thumbDrawable.setTint(Color.parseColor(this.I));
        } else {
            thumbDrawable.setTint(this.x.getColor(R.color.colorPrimaryOT));
        }
    }

    public final void R(JSONObject jSONObject) throws NumberFormatException {
        try {
            int iD = assistantMode.utils.studiableMetadata.b.d(this.x, this.M);
            com.onetrust.otpublishers.headless.UI.UIProperty.f fVar = new com.onetrust.otpublishers.headless.UI.UIProperty.f(this.x, iD);
            this.L = fVar.f();
            this.V = fVar.a.c();
            androidx.navigation.internal.m mVar = (androidx.navigation.internal.m) this.L.e;
            this.H = !com.onetrust.otpublishers.headless.Internal.a.j((String) mVar.b) ? (String) mVar.b : jSONObject.optString("PcTextColor");
            String str = (String) ((androidx.navigation.internal.m) this.L.g).b;
            String strOptString = jSONObject.optString("PcTextColor");
            String str2 = "#696969";
            if (com.onetrust.otpublishers.headless.Internal.a.j(str)) {
                str = !com.onetrust.otpublishers.headless.Internal.a.j(strOptString) ? strOptString : iD == 11 ? "#FFFFFF" : "#696969";
            }
            this.X = str;
            String str3 = (String) ((androidx.navigation.internal.m) this.L.f).b;
            String strOptString2 = jSONObject.optString("PcTextColor");
            if (com.onetrust.otpublishers.headless.Internal.a.j(str3)) {
                str3 = !com.onetrust.otpublishers.headless.Internal.a.j(strOptString2) ? strOptString2 : iD == 11 ? "#FFFFFF" : "#696969";
            }
            this.Y = str3;
            String str4 = (String) ((androidx.navigation.internal.m) this.L.h).b;
            String strOptString3 = jSONObject.optString("PcTextColor");
            if (com.onetrust.otpublishers.headless.Internal.a.j(str4)) {
                str4 = !com.onetrust.otpublishers.headless.Internal.a.j(strOptString3) ? strOptString3 : iD == 11 ? "#FFFFFF" : "#696969";
            }
            String str5 = (String) this.L.a;
            String strOptString4 = jSONObject.optString("PcBackgroundColor");
            if (com.onetrust.otpublishers.headless.Internal.a.j(str5)) {
                str5 = !com.onetrust.otpublishers.headless.Internal.a.j(strOptString4) ? strOptString4 : iD == 11 ? "#2F2F2F" : "#FFFFFF";
            }
            String str6 = (String) this.L.k;
            String strOptString5 = jSONObject.optString("PcTextColor");
            if (!com.onetrust.otpublishers.headless.Internal.a.j(str6)) {
                str2 = str6;
            } else if (!com.onetrust.otpublishers.headless.Internal.a.j(strOptString5)) {
                str2 = strOptString5;
            } else if (iD == 11) {
                str2 = "#FFFFFF";
            }
            S();
            assistantMode.utils.studiableMetadata.b bVar = this.W;
            androidx.navigation.internal.m mVar2 = (androidx.navigation.internal.m) ((com.quizlet.data.repository.user.e) this.L.j).b;
            String strOptString6 = jSONObject.optString("PcLinksTextColor");
            bVar.getClass();
            if (!com.onetrust.otpublishers.headless.Internal.a.j((String) mVar2.b)) {
                strOptString6 = (String) mVar2.b;
            }
            androidx.room.s sVar = this.V;
            if (sVar == null || sVar.c) {
                TextView textView = this.s;
                textView.setPaintFlags(textView.getPaintFlags() | 8);
            }
            a();
            assistantMode.utils.studiableMetadata.b.x(this.r, (String) ((androidx.navigation.internal.m) this.L.e).f);
            assistantMode.utils.studiableMetadata.b.x(this.t, (String) ((androidx.navigation.internal.m) this.L.h).f);
            com.google.android.gms.cloudmessaging.k kVar = (com.google.android.gms.cloudmessaging.k) ((androidx.navigation.internal.m) this.L.e).d;
            assistantMode.utils.studiableMetadata.b bVar2 = this.W;
            TextView textView2 = this.r;
            OTConfiguration oTConfiguration = this.M;
            bVar2.getClass();
            assistantMode.utils.studiableMetadata.b.w(textView2, kVar, oTConfiguration);
            com.google.android.gms.cloudmessaging.k kVar2 = (com.google.android.gms.cloudmessaging.k) ((androidx.navigation.internal.m) ((com.quizlet.data.repository.user.e) this.L.j).b).d;
            assistantMode.utils.studiableMetadata.b bVar3 = this.W;
            TextView textView3 = this.s;
            OTConfiguration oTConfiguration2 = this.M;
            bVar3.getClass();
            assistantMode.utils.studiableMetadata.b.w(textView3, kVar2, oTConfiguration2);
            com.google.android.gms.cloudmessaging.k kVar3 = (com.google.android.gms.cloudmessaging.k) ((androidx.navigation.internal.m) this.L.h).d;
            assistantMode.utils.studiableMetadata.b bVar4 = this.W;
            TextView textView4 = this.t;
            OTConfiguration oTConfiguration3 = this.M;
            bVar4.getClass();
            assistantMode.utils.studiableMetadata.b.w(textView4, kVar3, oTConfiguration3);
            this.r.setTextColor(Color.parseColor(this.H));
            this.t.setTextColor(Color.parseColor(str4));
            this.C.setBackgroundColor(Color.parseColor(str5));
            this.B.setBackgroundColor(Color.parseColor(str5));
            this.D.setBackgroundColor(Color.parseColor(str5));
            this.w.setColorFilter(Color.parseColor(str2));
            this.s.setTextColor(Color.parseColor(strOptString6));
        } catch (JSONException e) {
            Z.p("Error while applying styles to Vendor details, err : ", e, "OneTrust", 6);
        }
    }

    public final void S() {
        String str = (String) this.L.c;
        if (str != null && !com.onetrust.otpublishers.headless.Internal.a.j(str)) {
            this.J = (String) this.L.c;
        }
        String str2 = (String) this.L.b;
        if (str2 != null && !com.onetrust.otpublishers.headless.Internal.a.j(str2)) {
            this.I = (String) this.L.b;
        }
        String str3 = (String) this.L.d;
        if (str3 == null || com.onetrust.otpublishers.headless.Internal.a.j(str3)) {
            return;
        }
        this.K = (String) this.L.d;
    }

    public final void a() throws NumberFormatException {
        if (!com.onetrust.otpublishers.headless.Internal.a.j((String) ((com.google.android.gms.cloudmessaging.k) ((androidx.navigation.internal.m) this.L.e).d).d)) {
            this.r.setTextSize(Float.parseFloat((String) ((com.google.android.gms.cloudmessaging.k) ((androidx.navigation.internal.m) this.L.e).d).d));
        }
        if (!com.onetrust.otpublishers.headless.Internal.a.j((String) ((com.google.android.gms.cloudmessaging.k) ((androidx.navigation.internal.m) this.L.h).d).d)) {
            this.t.setTextSize(Float.parseFloat((String) ((com.google.android.gms.cloudmessaging.k) ((androidx.navigation.internal.m) this.L.h).d).d));
        }
        String str = (String) ((com.google.android.gms.cloudmessaging.k) ((androidx.navigation.internal.m) ((com.quizlet.data.repository.user.e) this.L.j).b).d).d;
        if (com.onetrust.otpublishers.headless.Internal.a.j(str)) {
            return;
        }
        this.s.setTextSize(Float.parseFloat(str));
    }

    @Override // android.view.View.OnClickListener
    public final void onClick(View view) {
        int id = view.getId();
        if (id != R.id.general_vendor_detail_back) {
            if (id == R.id.general_vendors_privacy_notice) {
                com.onetrust.otpublishers.headless.Internal.a.c(this.x, this.q);
                return;
            }
            return;
        }
        G();
        w wVar = this.F;
        wVar.getClass();
        com.google.firebase.perf.logging.b bVar = D.D;
        D this$0 = wVar.a;
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        this$0.X().D();
    }

    @Override // androidx.fragment.app.Fragment, android.content.ComponentCallbacks
    public final void onConfigurationChanged(Configuration configuration) {
        super.onConfigurationChanged(configuration);
        assistantMode.utils.studiableMetadata.b bVar = this.W;
        androidx.fragment.app.I activity = getActivity();
        com.google.android.material.bottomsheet.h hVar = this.v;
        bVar.getClass();
        assistantMode.utils.studiableMetadata.b.z(activity, hVar);
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, androidx.fragment.app.Fragment
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        setRetainInstance(true);
        if (this.y == null) {
            G();
        }
        androidx.fragment.app.I activity = getActivity();
        if (com.google.mlkit.common.internal.model.a.n(activity, OTFragmentTags.OT_GENERAL_VENDOR_DETAILS_TAG)) {
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
        com.onetrust.otpublishers.headless.Internal.Preferences.f fVar;
        String string;
        this.x = getContext();
        this.c1 = new com.onetrust.otpublishers.headless.UI.mobiledatautils.b();
        String strOptString = null;
        if (!this.c1.j(assistantMode.utils.studiableMetadata.b.d(this.x, this.M), this.x, this.y)) {
            G();
            return null;
        }
        Context context = this.x;
        boolean z = false;
        if (com.onetrust.otpublishers.headless.Internal.a.o(context)) {
            layoutInflater = layoutInflater.cloneInContext(new androidx.appcompat.view.d(context, R.style.Theme_AppCompat_Light_NoActionBar));
        }
        View viewInflate = layoutInflater.inflate(R.layout.ot_general_vendors_details_fragment, viewGroup, false);
        this.r = (TextView) viewInflate.findViewById(R.id.general_vendor_name);
        this.s = (TextView) viewInflate.findViewById(R.id.general_vendors_privacy_notice);
        this.B = (RelativeLayout) viewInflate.findViewById(R.id.general_vendor_detail_header);
        this.C = (RelativeLayout) viewInflate.findViewById(R.id.general_vendor_detail_RL);
        this.w = (ImageView) viewInflate.findViewById(R.id.general_vendor_detail_back);
        this.A = (SwitchCompat) viewInflate.findViewById(R.id.general_consent_switch);
        this.D = (LinearLayout) viewInflate.findViewById(R.id.gvd_linearLyt);
        this.t = (TextView) viewInflate.findViewById(R.id.general_consent_title);
        this.G = viewInflate.findViewById(R.id.general_vendor_name_view);
        this.u = (RecyclerView) viewInflate.findViewById(R.id.general_vendor_sdk_list);
        com.google.mlkit.common.internal.model.a.f(this.x, viewInflate, "VendorDetail");
        this.W = new assistantMode.utils.studiableMetadata.b(22);
        try {
            JSONObject preferenceCenterData = this.y.getPreferenceCenterData();
            if (preferenceCenterData != null) {
                R(preferenceCenterData);
                String strOptString2 = preferenceCenterData.optString("BConsentText");
                this.t.setText(strOptString2);
                this.A.setContentDescription(strOptString2);
                Context context2 = this.x;
                try {
                    SharedPreferences sharedPreferences = context2.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
                    if (new com.onetrust.otpublishers.headless.Internal.profile.c(context2).t()) {
                        fVar = new com.onetrust.otpublishers.headless.Internal.Preferences.f(context2, sharedPreferences, sharedPreferences.getString("OT_ACTIVE_PROFILE_ID", ""));
                        z = true;
                    } else {
                        fVar = null;
                    }
                    if (z) {
                        sharedPreferences = fVar;
                    }
                    try {
                        string = sharedPreferences.getString("OT_MOBILE_DATA", "");
                    } catch (JSONException e) {
                        OTLogger.c("OneTrust", 6, "error while getting mobile data json, err: " + e.getMessage());
                    }
                    JSONObject jSONObject = !com.onetrust.otpublishers.headless.Internal.a.j(string) ? new JSONObject(string) : new JSONObject();
                    JSONObject jSONObject2 = jSONObject.has("preferenceCenterData") ? jSONObject.getJSONObject("preferenceCenterData") : new JSONObject();
                    if (jSONObject2.has("generalVendors")) {
                        JSONObject jSONObject3 = jSONObject2.getJSONObject("generalVendors");
                        if (jSONObject3.has(OTVendorListMode.GENERAL)) {
                            JSONObject jSONObject4 = jSONObject3.getJSONObject(OTVendorListMode.GENERAL);
                            jSONObject4.optString("text");
                            strOptString = jSONObject4.optString("vendorListPrivacyPolicyText");
                            jSONObject4.optString("vendorListLabelText");
                        }
                    }
                } catch (JSONException e2) {
                    OTLogger.c("GeneralVendors", 6, "Error while parsing General Vendor labels:" + e2);
                }
                if (getArguments() != null) {
                    String string2 = getArguments().getString("vendorId");
                    this.E = string2;
                    this.z = this.y.getVendorDetails(OTVendorListMode.GENERAL, string2);
                    a(preferenceCenterData);
                    if (com.onetrust.otpublishers.headless.Internal.a.j(strOptString) || com.onetrust.otpublishers.headless.Internal.a.j(this.q)) {
                        this.s.setVisibility(8);
                    } else {
                        this.s.setText(strOptString);
                    }
                    if (preferenceCenterData.has("PCPrivacyLinkActionAriaLabel")) {
                        com.google.mlkit.common.internal.model.a.k(this.s, preferenceCenterData.optString("PCPrivacyLinkActionAriaLabel"));
                    }
                    if (preferenceCenterData.has("PCenterBackText")) {
                        this.w.setContentDescription(preferenceCenterData.optString("PCenterBackText"));
                    }
                }
            }
        } catch (Exception e3) {
            Z.n("error while populating Vendor Detail fields", e3, "VendorDetail", 6);
        }
        this.s.setOnClickListener(this);
        this.w.setOnClickListener(this);
        this.A.setOnClickListener(new com.braze.ui.inappmessage.d(this, 8));
        return viewInflate;
    }

    @Override // androidx.fragment.app.Fragment
    public final void onResume() throws JSONException, Resources.NotFoundException {
        com.onetrust.otpublishers.headless.Internal.Preferences.f fVar;
        boolean z;
        Drawable trackDrawable;
        int color;
        Drawable thumbDrawable;
        int color2;
        super.onResume();
        try {
            Context context = this.x;
            SharedPreferences sharedPreferences = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
            if (AbstractC3605e0.a(new com.onetrust.otpublishers.headless.Internal.Preferences.d(context, "OTT_DEFAULT_USER").b().getString("OT_ENABLE_MULTI_PROFILE", Boolean.FALSE.toString()))) {
                fVar = new com.onetrust.otpublishers.headless.Internal.Preferences.f(context, sharedPreferences, sharedPreferences.getString("OT_ACTIVE_PROFILE_ID", ""));
                z = true;
            } else {
                fVar = null;
                z = false;
            }
            if (z) {
                sharedPreferences = fVar;
            }
            if (sharedPreferences.getBoolean("OT_GENERAL_VENDORS_TOGGLE_CONFIGURED", false)) {
                int i = this.z.getInt(OTVendorUtils.CONSENT_TYPE);
                if (i == 0) {
                    this.A.setChecked(false);
                    SwitchCompat switchCompat = this.A;
                    if (this.K != null) {
                        trackDrawable = switchCompat.getTrackDrawable();
                        color = Color.parseColor(this.K);
                    } else {
                        trackDrawable = switchCompat.getTrackDrawable();
                        color = this.x.getColor(R.color.light_greyOT);
                    }
                    trackDrawable.setTint(color);
                    if (this.J != null) {
                        thumbDrawable = switchCompat.getThumbDrawable();
                        color2 = Color.parseColor(this.J);
                    } else {
                        thumbDrawable = switchCompat.getThumbDrawable();
                        color2 = this.x.getColor(R.color.contentTextColorOT);
                    }
                    thumbDrawable.setTint(color2);
                    return;
                }
                if (i == 1) {
                    this.A.setChecked(true);
                    Q(this.A);
                    return;
                } else if (i == 2) {
                    this.A.setChecked(true);
                    Q(this.A);
                    this.A.setEnabled(false);
                    this.A.setAlpha(0.5f);
                    return;
                }
            }
            this.A.setVisibility(8);
            this.t.setVisibility(8);
            this.G.setVisibility(8);
        } catch (JSONException e) {
            Z.p("error while setting toggle values", e, "VendorDetail", 6);
        }
    }

    public final void a(JSONObject jSONObject) throws JSONException {
        JSONObject jSONObject2 = this.z;
        if (jSONObject2 != null) {
            this.r.setText(jSONObject2.getString("Name"));
            V.p(this.r, true);
            this.r.setLabelFor(R.id.general_consent_switch);
            this.q = this.z.getString("PrivacyPolicyUrl");
            String string = this.z.getString("Description");
            JSONArray jSONArray = this.z.getJSONArray("Sdks");
            if (retrofit2.adapter.rxjava3.d.l(jSONArray) && com.onetrust.otpublishers.headless.Internal.a.j(string) && !this.c1.u.i) {
                return;
            }
            String strOptString = jSONObject.optString("PCenterCookiesListText");
            if (retrofit2.adapter.rxjava3.d.l(jSONArray)) {
                jSONArray = new JSONArray();
                strOptString = "";
            }
            JSONArray jSONArray2 = jSONArray;
            this.u.setLayoutManager(new LinearLayoutManager(this.x));
            this.u.setAdapter(new C4046b(this.x, jSONArray2, this.X, this.L, this.M, strOptString, Color.parseColor(this.Y), this.L, string, this.c1));
        }
    }
}

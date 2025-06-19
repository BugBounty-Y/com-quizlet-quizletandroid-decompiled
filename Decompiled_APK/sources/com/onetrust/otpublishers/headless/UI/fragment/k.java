package com.onetrust.otpublishers.headless.UI.fragment;

import android.app.Dialog;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.res.Configuration;
import android.content.res.Resources;
import android.graphics.Color;
import android.graphics.Typeface;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.appcompat.widget.SwitchCompat;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.google.android.gms.internal.ads.Zh;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3206m6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3705q4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.Q;
import com.google.android.gms.internal.mlkit_vision_document_scanner.W;
import com.google.android.gms.internal.mlkit_vision_document_scanner.Y;
import com.google.android.gms.measurement.internal.Z;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.onetrust.otpublishers.headless.Public.DataModel.OTConfiguration;
import com.onetrust.otpublishers.headless.Public.Keys.OTFragmentTags;
import com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK;
import com.onetrust.otpublishers.headless.Public.OTThemeConstants;
import com.onetrust.otpublishers.headless.UI.adapter.C4053i;
import com.quizlet.quizletandroid.R;
import java.util.ArrayList;
import java.util.HashMap;
import kotlin.Pair;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public class k extends com.google.android.material.bottomsheet.i implements View.OnClickListener, com.onetrust.otpublishers.headless.UI.a, com.onetrust.otpublishers.headless.UI.adapter.t {
    public TextView A;
    public boolean A1;
    public TextView B;
    public boolean B1;
    public TextView C;
    public JSONObject C1;
    public TextView D;
    public JSONObject D1;
    public TextView E;
    public String E1;
    public TextView F;
    public assistantMode.utils.studiableMetadata.b F1;
    public TextView G;
    public TextView H;
    public String H1;
    public TextView I;
    public Zh I1;
    public TextView J;
    public OTConfiguration J1;
    public TextView K;
    public androidx.room.s K1;
    public TextView L;
    public com.onetrust.otpublishers.headless.UI.mobiledatautils.b L1;
    public TextView M;
    public com.onetrust.otpublishers.headless.UI.mobiledatautils.c M1;
    public String N1;
    public JSONObject O1;
    public TextView V;
    public TextView W;
    public TextView X;
    public TextView Y;
    public com.google.android.material.bottomsheet.h Z;
    public C4053i c1;
    public Context d1;
    public OTPublishersHeadlessSDK e1;
    public com.onetrust.otpublishers.headless.UI.adapter.m f1;
    public SwitchCompat g1;
    public SwitchCompat h1;
    public SwitchCompat i1;
    public SwitchCompat j1;
    public SwitchCompat k1;
    public SwitchCompat l1;
    public RecyclerView m1;
    public RelativeLayout n1;
    public RelativeLayout o1;
    public String p1;
    public boolean q;
    public String q1;
    public TextView r;
    public String r1;
    public TextView s;
    public FrameLayout s1;
    public TextView t;
    public ImageView t1;
    public TextView u;
    public TextView u1;
    public TextView v;
    public D v1;
    public TextView w;
    public s w1;
    public TextView x;
    public TextView y;
    public boolean y1;
    public TextView z;
    public boolean z1;
    public com.onetrust.otpublishers.headless.Internal.Event.a x1 = new com.onetrust.otpublishers.headless.Internal.Event.a();
    public final HashMap G1 = new HashMap();

    @Override // com.google.android.material.bottomsheet.i, androidx.appcompat.app.E, androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t
    public final Dialog K(Bundle bundle) {
        Dialog dialogK = super.K(bundle);
        dialogK.setOnShowListener(new com.onetrust.otpublishers.headless.UI.TVUI.fragments.e(this, 5));
        return dialogK;
    }

    public final void Q(TextView textView, androidx.navigation.internal.m mVar) throws NumberFormatException {
        Typeface otTypeFaceMap;
        textView.setText((String) mVar.g);
        textView.setTextColor(Color.parseColor((String) mVar.b));
        com.google.android.gms.cloudmessaging.k kVar = (com.google.android.gms.cloudmessaging.k) mVar.d;
        OTConfiguration oTConfiguration = this.J1;
        String str = (String) kVar.e;
        if (com.onetrust.otpublishers.headless.Internal.a.j(str) || oTConfiguration == null || (otTypeFaceMap = oTConfiguration.getOtTypeFaceMap(str)) == null) {
            int iA = com.google.android.gms.cloudmessaging.k.a(textView, kVar.b);
            textView.setTypeface(!com.onetrust.otpublishers.headless.Internal.a.j((String) kVar.c) ? Typeface.create((String) kVar.c, iA) : Typeface.create(textView.getTypeface(), iA));
        } else {
            textView.setTypeface(otTypeFaceMap);
        }
        if (!com.onetrust.otpublishers.headless.Internal.a.j((String) kVar.d)) {
            textView.setTextSize(Float.parseFloat((String) kVar.d));
        }
        assistantMode.utils.studiableMetadata.b.x(textView, (String) mVar.f);
    }

    public final void R(SwitchCompat switchCompat, boolean z) {
        assistantMode.utils.studiableMetadata.b bVar;
        Context context;
        String str;
        String str2;
        if (z) {
            bVar = this.F1;
            context = this.d1;
            Zh zh = this.M1.l;
            str = (String) zh.f;
            str2 = (String) zh.d;
        } else {
            bVar = this.F1;
            context = this.d1;
            Zh zh2 = this.M1.l;
            str = (String) zh2.f;
            str2 = (String) zh2.e;
        }
        bVar.getClass();
        assistantMode.utils.studiableMetadata.b.s(context, switchCompat, str, str2);
    }

    public final void S(String str, boolean z) {
        com.onetrust.otpublishers.headless.Internal.Preferences.f fVar;
        boolean z2;
        Context context = this.d1;
        new JSONObject();
        SharedPreferences sharedPreferences = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
        if (Q.a(context)) {
            fVar = new com.onetrust.otpublishers.headless.Internal.Preferences.f(context, sharedPreferences, sharedPreferences.getString("OT_ACTIVE_PROFILE_ID", ""));
            z2 = true;
        } else {
            fVar = null;
            z2 = false;
        }
        if (z2) {
            sharedPreferences = fVar;
        }
        new com.onetrust.otpublishers.headless.Internal.Preferences.d(context);
        String string = sharedPreferences.getString("OTT_INTERNAL_SDK_GROUP_MAP", "");
        JSONArray jSONArray = new JSONArray();
        if (!com.onetrust.otpublishers.headless.Internal.a.j(string)) {
            try {
                JSONObject jSONObject = new JSONObject(string);
                if (jSONObject.has(str)) {
                    jSONArray = new JSONArray(jSONObject.get(str).toString());
                }
            } catch (JSONException e) {
                Z.p("Error while fetching Sdks by group : ", e, "SdkListHelper", 6);
            }
        }
        for (int i = 0; i < jSONArray.length(); i++) {
            try {
                this.e1.updateSDKConsentStatus(jSONArray.get(i).toString(), z);
            } catch (JSONException e2) {
                Z.p("Error while Updating consent of SDK ", e2, "OTPCDetail", 6);
            }
        }
    }

    public final void T(String str, boolean z, SwitchCompat switchCompat) {
        OTLogger.c("OTPCDetail", 3, "Updating consent of parent :" + z);
        this.e1.updatePurposeConsent(str, z);
        androidx.compose.foundation.lazy.grid.m mVar = new androidx.compose.foundation.lazy.grid.m(7, 4);
        mVar.c = str;
        mVar.b = z ? 1 : 0;
        assistantMode.utils.studiableMetadata.b bVar = this.F1;
        com.onetrust.otpublishers.headless.Internal.Event.a aVar = this.x1;
        bVar.getClass();
        assistantMode.utils.studiableMetadata.b.y(mVar, aVar);
        R(switchCompat, z);
    }

    public final void U(String str, boolean z, boolean z2) throws JSONException, Resources.NotFoundException {
        SwitchCompat switchCompat;
        if (z2) {
            this.h1.setChecked(z);
            this.e1.updatePurposeLegitInterest(str, z);
            switchCompat = this.h1;
        } else if (this.q) {
            this.g1.setChecked(z);
            this.e1.updatePurposeConsent(str, z);
            switchCompat = this.g1;
        } else {
            this.l1.setChecked(z);
            this.e1.updatePurposeConsent(str, z);
            switchCompat = this.l1;
        }
        R(switchCompat, z);
    }

    /* JADX WARN: Removed duplicated region for block: B:104:0x02c1  */
    /* JADX WARN: Removed duplicated region for block: B:114:0x0311  */
    /* JADX WARN: Removed duplicated region for block: B:68:0x01cd A[PHI: r0
  0x01cd: PHI (r0v105 java.lang.String) = (r0v102 java.lang.String), (r0v112 java.lang.String) binds: [B:67:0x01cb, B:62:0x01ac] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:69:0x01dd  */
    /* JADX WARN: Removed duplicated region for block: B:75:0x01f6  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void V() throws org.json.JSONException {
        /*
            Method dump skipped, instructions count: 882
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.UI.fragment.k.V():void");
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r6v0 */
    /* JADX WARN: Type inference failed for: r6v1, types: [boolean, int] */
    /* JADX WARN: Type inference failed for: r6v2 */
    public final void W(SwitchCompat switchCompat, boolean z) throws JSONException {
        int i;
        com.onetrust.otpublishers.headless.Internal.Preferences.f fVar;
        boolean z2;
        if (this.C1.has("SubGroups")) {
            com.onetrust.otpublishers.headless.UI.mobiledatautils.c cVar = this.M1;
            JSONArray jSONArray = this.C1.getJSONArray("SubGroups");
            boolean zIsChecked = switchCompat.isChecked();
            OTPublishersHeadlessSDK oTPublishersHeadlessSDK = this.e1;
            cVar.getClass();
            ?? r6 = 0;
            int i2 = 0;
            while (i2 < jSONArray.length()) {
                JSONObject jSONObject = jSONArray.getJSONObject(i2);
                boolean zOptBoolean = jSONObject.optBoolean("HasConsentOptOut", r6);
                String string = jSONObject.getString("CustomGroupId");
                if (z) {
                    i = r6;
                    if (oTPublishersHeadlessSDK.getPurposeLegitInterestLocal(string) >= 0) {
                        oTPublishersHeadlessSDK.updatePurposeLegitInterest(string, zIsChecked);
                    }
                } else if (zOptBoolean) {
                    oTPublishersHeadlessSDK.updatePurposeConsent(string, zIsChecked);
                    Context context = cVar.o;
                    new JSONObject();
                    SharedPreferences sharedPreferences = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", r6);
                    SharedPreferences sharedPreferences2 = context.getSharedPreferences("com.onetrust.otpublishers.headless.preference".concat("OTT_DEFAULT_USER"), r6);
                    Boolean bool = Boolean.FALSE;
                    if (Z.r(bool, sharedPreferences2, "OT_ENABLE_MULTI_PROFILE")) {
                        fVar = new com.onetrust.otpublishers.headless.Internal.Preferences.f(context, sharedPreferences, sharedPreferences.getString("OT_ACTIVE_PROFILE_ID", ""));
                        z2 = true;
                    } else {
                        fVar = null;
                        z2 = false;
                    }
                    if (z2) {
                        sharedPreferences = fVar;
                    }
                    SharedPreferences sharedPreferences3 = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
                    if (Z.r(bool, Y.a(context), "OT_ENABLE_MULTI_PROFILE")) {
                        i = 0;
                        SharedPreferences sharedPreferences4 = context.getSharedPreferences("com.onetrust.otpublishers.headless.preference.OTT_USER_" + new com.onetrust.otpublishers.headless.Internal.profile.c(context).n(sharedPreferences3.getString("OT_ACTIVE_PROFILE_ID", "")), 0);
                        sharedPreferences3.edit();
                        sharedPreferences4.edit();
                    } else {
                        i = 0;
                    }
                    String string2 = sharedPreferences.getString("OTT_INTERNAL_SDK_GROUP_MAP", "");
                    JSONArray jSONArray2 = new JSONArray();
                    if (!com.onetrust.otpublishers.headless.Internal.a.j(string2)) {
                        try {
                            JSONObject jSONObject2 = new JSONObject(string2);
                            if (jSONObject2.has(string)) {
                                jSONArray2 = new JSONArray(jSONObject2.get(string).toString());
                            }
                        } catch (JSONException e) {
                            Z.p("Error while fetching Sdks by group : ", e, "SdkListHelper", 6);
                        }
                    }
                    OTLogger.c("PC Detail", 4, "SDKs of group : " + string + " is " + jSONArray2);
                    for (int i3 = i; i3 < jSONArray2.length(); i3++) {
                        try {
                            cVar.n.updateSDKConsentStatus(jSONArray2.get(i3).toString(), zIsChecked);
                        } catch (JSONException e2) {
                            Z.p("Error in setting group sdk status ", e2, "OneTrust", 6);
                        }
                    }
                } else {
                    i = r6;
                }
                i2++;
                r6 = i;
            }
            this.c1.notifyDataSetChanged();
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:120:0x0400  */
    /* JADX WARN: Removed duplicated region for block: B:145:0x0490  */
    /* JADX WARN: Removed duplicated region for block: B:147:0x04ae  */
    /* JADX WARN: Removed duplicated region for block: B:150:0x04bd  */
    /* JADX WARN: Removed duplicated region for block: B:152:0x04c3  */
    /* JADX WARN: Removed duplicated region for block: B:174:0x058e  */
    /* JADX WARN: Removed duplicated region for block: B:212:0x06cc  */
    /* JADX WARN: Removed duplicated region for block: B:69:0x0327  */
    /* JADX WARN: Removed duplicated region for block: B:95:0x03a4  */
    /* JADX WARN: Type inference failed for: r0v143, types: [org.json.JSONObject] */
    /* JADX WARN: Type inference failed for: r0v149, types: [android.view.View, android.widget.TextView] */
    /* JADX WARN: Type inference failed for: r0v150, types: [android.view.View, android.widget.TextView] */
    /* JADX WARN: Type inference failed for: r0v151, types: [android.view.View, android.widget.TextView] */
    /* JADX WARN: Type inference failed for: r0v155, types: [android.view.View] */
    /* JADX WARN: Type inference failed for: r0v160, types: [android.view.View, android.widget.TextView] */
    /* JADX WARN: Type inference failed for: r0v161, types: [android.view.View, android.widget.TextView] */
    /* JADX WARN: Type inference failed for: r0v162, types: [android.view.View, android.widget.TextView] */
    /* JADX WARN: Type inference failed for: r0v248 */
    /* JADX WARN: Type inference failed for: r0v249 */
    /* JADX WARN: Type inference failed for: r0v250 */
    /* JADX WARN: Type inference failed for: r0v251 */
    /* JADX WARN: Type inference failed for: r0v36, types: [android.view.View, android.widget.RelativeLayout] */
    /* JADX WARN: Type inference failed for: r0v37, types: [org.json.JSONObject] */
    /* JADX WARN: Type inference failed for: r0v87, types: [android.view.View] */
    /* JADX WARN: Type inference failed for: r11v6, types: [int] */
    /* JADX WARN: Type inference failed for: r11v7 */
    /* JADX WARN: Type inference failed for: r11v9 */
    /* JADX WARN: Type inference failed for: r2v25 */
    /* JADX WARN: Type inference failed for: r2v26 */
    /* JADX WARN: Type inference failed for: r2v28, types: [boolean, int] */
    /* JADX WARN: Type inference failed for: r2v43 */
    /* JADX WARN: Type inference failed for: r2v48 */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void X() throws org.json.JSONException, android.content.res.Resources.NotFoundException {
        /*
            Method dump skipped, instructions count: 2015
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.UI.fragment.k.X():void");
    }

    public final void Y() throws Resources.NotFoundException {
        String str = this.M1.d;
        boolean z = this.e1.getPurposeConsentLocal(str) == 1;
        if (!this.q) {
            this.l1.setChecked(z);
            R(this.l1, z);
            this.k1.setChecked(z);
            R(this.k1, z);
            return;
        }
        boolean z2 = this.e1.getPurposeLegitInterestLocal(str) == 1;
        this.g1.setChecked(z);
        this.h1.setChecked(z2);
        R(this.g1, z);
        R(this.h1, z2);
        this.i1.setChecked(z);
        R(this.i1, z);
        this.j1.setChecked(z2);
        R(this.j1, z2);
    }

    @Override // com.onetrust.otpublishers.headless.UI.adapter.t
    public final void a() {
        Y();
        C4053i c4053i = this.c1;
        if (c4053i != null) {
            c4053i.notifyDataSetChanged();
        }
    }

    public final void a0() {
        Zh zh = this.I1;
        String str = (String) ((androidx.navigation.internal.m) zh.k).g;
        String str2 = (String) ((androidx.navigation.internal.m) zh.l).g;
        this.g1.setContentDescription(str);
        this.i1.setContentDescription(str);
        this.k1.setContentDescription(str);
        this.l1.setContentDescription(str);
        this.j1.setContentDescription(str2);
        this.h1.setContentDescription(str2);
    }

    public final void b0() {
        TextView textView;
        if (!this.B1 || this.r1 == null || !com.onetrust.otpublishers.headless.UI.mobiledatautils.c.e(this.C1)) {
            this.J.setVisibility(8);
            this.K.setVisibility(8);
            this.V.setVisibility(8);
        } else {
            if (this.r1.equals("bottom")) {
                this.W.setVisibility(0);
                this.J.setVisibility(8);
                textView = this.K;
                textView.setVisibility(8);
            }
            if (!this.r1.equals("top")) {
                return;
            }
            this.J.setVisibility(0);
            this.K.setVisibility(0);
            this.V.setVisibility(8);
        }
        textView = this.W;
        textView.setVisibility(8);
    }

    @Override // android.view.View.OnClickListener
    public final void onClick(View view) throws JSONException {
        int id = view.getId();
        if (id == R.id.back_to_pc) {
            G();
            com.onetrust.otpublishers.headless.UI.adapter.m mVar = this.f1;
            if (mVar != null) {
                mVar.p(4);
                return;
            }
            return;
        }
        boolean z = false;
        if (id == R.id.vendors_list_link || id == R.id.vendors_list_link_below || id == R.id.vendors_list_link_parent || id == R.id.vendors_list_link_parent_below_combined) {
            if (this.v1.isAdded() || getActivity() == null) {
                return;
            }
            try {
                if (!this.C1.optBoolean("IsIabPurpose") && com.onetrust.otpublishers.headless.UI.mobiledatautils.c.c(this.C1)) {
                    z = true;
                }
                HashMap map = this.G1;
                Bundle bundleA = z ? this.M1.a(map) : this.M1.d(map);
                bundleA.putBoolean("generalVendors", z);
                this.v1.setArguments(bundleA);
                D d = this.v1;
                d.v = this;
                com.google.mlkit.common.internal.model.a.o(d, requireActivity(), OTFragmentTags.OT_VENDOR_LIST_FRAGMENT_TAG);
                assistantMode.utils.studiableMetadata.b bVar = this.F1;
                androidx.compose.foundation.lazy.grid.m mVar2 = new androidx.compose.foundation.lazy.grid.m(12, 4);
                com.onetrust.otpublishers.headless.Internal.Event.a aVar = this.x1;
                bVar.getClass();
                assistantMode.utils.studiableMetadata.b.y(mVar2, aVar);
                return;
            } catch (JSONException e) {
                W.a("error thrown onClick: Vendor list link ", e, "OTPCDetail", 6);
                return;
            }
        }
        if (id == R.id.view_legal_text || id == R.id.view_legal_text_below || id == R.id.view_legal_text_parent || id == R.id.view_legal_text_parent_below_combined || id == R.id.view_legal_text_parent_below) {
            com.onetrust.otpublishers.headless.Internal.a.c(this.d1, this.M1.h);
            return;
        }
        if (id != R.id.sdk_list_link && id != R.id.sdk_list_link_child && id != R.id.sdk_list_link_child_below && id != R.id.sdk_list_link_parent_below_combined) {
            if (id == R.id.view_iab_illustration) {
                OTConfiguration oTConfiguration = this.J1;
                JSONObject jSONObject = this.C1;
                ViewOnClickListenerC4065i viewOnClickListenerC4065i = new ViewOnClickListenerC4065i();
                Bundle bundle = new Bundle();
                bundle.putString("string", OTFragmentTags.OT_IAB_ILLUSTRATION_DETAILS_TAG);
                viewOnClickListenerC4065i.setArguments(bundle);
                viewOnClickListenerC4065i.B = oTConfiguration;
                viewOnClickListenerC4065i.F = jSONObject;
                viewOnClickListenerC4065i.w = this.e1;
                if (viewOnClickListenerC4065i.isAdded()) {
                    return;
                }
                com.google.mlkit.common.internal.model.a.o(viewOnClickListenerC4065i, requireActivity(), OTFragmentTags.OT_IAB_ILLUSTRATION_DETAILS_TAG);
                return;
            }
            return;
        }
        if (this.w1.isAdded() || getActivity() == null) {
            return;
        }
        Bundle bundle2 = new Bundle();
        try {
            ArrayList arrayList = new ArrayList();
            JSONObject jSONObject2 = this.C1;
            if (!jSONObject2.optBoolean("ShowSubgroup", false) || jSONObject2.getJSONArray("FirstPartyCookies").length() > 0) {
                arrayList.add(jSONObject2.getString("CustomGroupId"));
            }
            if (this.C1.has("SubGroups") && this.C1.optBoolean("ShowSubgroup", false)) {
                JSONArray jSONArray = this.C1.getJSONArray("SubGroups");
                for (int i = 0; i < jSONArray.length(); i++) {
                    JSONObject jSONObject3 = jSONArray.getJSONObject(i);
                    if (!jSONObject3.optBoolean("ShowSubgroup", false) || jSONObject3.getJSONArray("FirstPartyCookies").length() > 0) {
                        arrayList.add(jSONObject3.getString("CustomGroupId"));
                    }
                }
            }
            bundle2.putString("OT_GROUP_ID_LIST", arrayList.toString());
            bundle2.putString("GroupName", this.C1.getString("GroupName"));
            bundle2.putString("CustomGroupId", this.C1.getString("CustomGroupId"));
            bundle2.putString("sdkLevelOptOutShow", this.N1);
            bundle2.putString("SDK_LIST_VIEW_TITLE", (String) ((androidx.navigation.internal.m) ((com.quizlet.data.repository.user.e) this.I1.n).b).g);
            bundle2.putString("ALWAYS_ACTIVE_TEXT", (String) ((androidx.navigation.internal.m) this.I1.m).g);
            bundle2.putString("ALWAYS_ACTIVE_TEXT_COLOR", (String) ((androidx.navigation.internal.m) this.I1.m).b);
        } catch (JSONException e2) {
            Z.p("error in passing sdklist : ", e2, "OTPCDetail", 6);
        }
        this.w1.setArguments(bundle2);
        com.google.mlkit.common.internal.model.a.o(this.w1, requireActivity(), OTFragmentTags.OT_SDK_LIST_FRAGMENT_TAG);
    }

    @Override // androidx.fragment.app.Fragment, android.content.ComponentCallbacks
    public final void onConfigurationChanged(Configuration configuration) {
        super.onConfigurationChanged(configuration);
        assistantMode.utils.studiableMetadata.b bVar = this.F1;
        androidx.fragment.app.I activity = getActivity();
        com.google.android.material.bottomsheet.h hVar = this.Z;
        bVar.getClass();
        assistantMode.utils.studiableMetadata.b.z(activity, hVar);
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, androidx.fragment.app.Fragment
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        setRetainInstance(true);
        Context applicationContext = getContext().getApplicationContext();
        if (applicationContext != null && this.e1 == null) {
            this.e1 = new OTPublishersHeadlessSDK(applicationContext);
        }
        androidx.fragment.app.I activity = getActivity();
        if (com.google.mlkit.common.internal.model.a.n(activity, OTFragmentTags.OT_PREFERENCE_CENTER_DETAILS_FRAGMENT_TAG)) {
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
    public final View onCreateView(LayoutInflater layoutInflater, ViewGroup viewGroup, Bundle bundle) throws Resources.NotFoundException {
        String string;
        JSONObject jSONObject;
        this.d1 = getContext();
        com.google.firebase.perf.logging.b bVar = D.D;
        com.onetrust.otpublishers.headless.Internal.Event.a aVar = this.x1;
        OTConfiguration oTConfiguration = this.J1;
        bVar.getClass();
        D dA = com.google.firebase.perf.logging.b.a(aVar, oTConfiguration);
        this.v1 = dA;
        dA.R(this.e1);
        OTConfiguration oTConfiguration2 = this.J1;
        Intrinsics.checkNotNullParameter(OTFragmentTags.OT_SDK_LIST_FRAGMENT_TAG, "fragmentTag");
        Bundle bundleA = AbstractC3206m6.a(new Pair(OTFragmentTags.FRAGMENT_TAG, OTFragmentTags.OT_SDK_LIST_FRAGMENT_TAG));
        s sVar = new s();
        sVar.setArguments(bundleA);
        sVar.t = oTConfiguration2;
        this.w1 = sVar;
        Intrinsics.checkNotNullParameter(this, "listener");
        sVar.v = this;
        s sVar2 = this.w1;
        OTPublishersHeadlessSDK otPublishersHeadlessSDK = this.e1;
        sVar2.getClass();
        Intrinsics.checkNotNullParameter(otPublishersHeadlessSDK, "otPublishersHeadlessSDK");
        sVar2.s = otPublishersHeadlessSDK;
        this.F1 = new assistantMode.utils.studiableMetadata.b(22);
        Bundle arguments = getArguments();
        com.onetrust.otpublishers.headless.UI.mobiledatautils.c cVar = new com.onetrust.otpublishers.headless.UI.mobiledatautils.c();
        cVar.a = new JSONObject();
        boolean z = false;
        cVar.i = false;
        this.M1 = cVar;
        if (arguments != null) {
            string = arguments.getString("SUBGROUP_ARRAY");
            arguments.getInt("PARENT_POSITION");
            this.N1 = arguments.getString("sdkLevelOptOutShow");
        } else {
            string = "";
        }
        int iD = assistantMode.utils.studiableMetadata.b.d(this.d1, this.J1);
        com.onetrust.otpublishers.headless.UI.mobiledatautils.c cVar2 = this.M1;
        Context context = this.d1;
        OTPublishersHeadlessSDK oTPublishersHeadlessSDK = this.e1;
        cVar2.getClass();
        if (!com.onetrust.otpublishers.headless.Internal.a.j(string)) {
            try {
                JSONObject jSONObject2 = new JSONObject(string);
                cVar2.a = jSONObject2;
                cVar2.e = jSONObject2.optBoolean("ShowSubgroup", false);
                cVar2.f = cVar2.a.optBoolean("ShowSubgroupToggle", false);
                cVar2.g = cVar2.a.optBoolean("ShowSubGroupDescription", false);
                cVar2.b = cVar2.a.optString("Type", "");
                cVar2.c = cVar2.a.optString("Type").equalsIgnoreCase("IAB2_STACK") || cVar2.a.optString("Type").equalsIgnoreCase("IAB2V2_STACK");
                cVar2.d = cVar2.a.optString("CustomGroupId");
                com.onetrust.otpublishers.headless.UI.UIProperty.f fVar = new com.onetrust.otpublishers.headless.UI.UIProperty.f(context, iD);
                cVar2.l = fVar.e();
                cVar2.m = fVar.a.c();
                JSONObject preferenceCenterData = oTPublishersHeadlessSDK.getPreferenceCenterData();
                if (preferenceCenterData != null) {
                    cVar2.h = preferenceCenterData.optString("IabLegalTextUrl");
                    cVar2.i = preferenceCenterData.optBoolean("IsIabEnabled");
                    cVar2.j = preferenceCenterData.optString("IabType");
                    cVar2.n = oTPublishersHeadlessSDK;
                    cVar2.o = context;
                    cVar2.k = preferenceCenterData.optString("PCGrpDescType", "");
                    androidx.navigation.internal.m mVar = (androidx.navigation.internal.m) cVar2.l.m;
                    if (com.onetrust.otpublishers.headless.Internal.a.j((String) mVar.g)) {
                        mVar.g = preferenceCenterData.optString("AlwaysActiveText", "");
                    }
                    if (com.onetrust.otpublishers.headless.Internal.a.j((String) mVar.b)) {
                        String str = (String) mVar.b;
                        String strOptString = preferenceCenterData.optString("PcLinksTextColor");
                        if (com.onetrust.otpublishers.headless.Internal.a.j(str)) {
                            str = !com.onetrust.otpublishers.headless.Internal.a.j(strOptString) ? strOptString : "#3860BE";
                        }
                        mVar.b = str;
                    }
                    Zh zh = cVar2.l;
                    zh.m = mVar;
                    if (com.onetrust.otpublishers.headless.Internal.a.j((String) zh.g)) {
                        cVar2.l.g = preferenceCenterData.getString("PcTextColor");
                    }
                    if (com.onetrust.otpublishers.headless.Internal.a.j((String) cVar2.l.b)) {
                        cVar2.l.b = preferenceCenterData.getString("PcBackgroundColor");
                    }
                    if (com.onetrust.otpublishers.headless.Internal.a.j((String) cVar2.l.f)) {
                        cVar2.l.f = "#d1d1d1";
                    }
                    if (com.onetrust.otpublishers.headless.Internal.a.j((String) cVar2.l.d)) {
                        cVar2.l.d = "#67B54B";
                    }
                    if (com.onetrust.otpublishers.headless.Internal.a.j((String) cVar2.l.e)) {
                        cVar2.l.e = "#788381";
                    }
                    androidx.navigation.internal.m mVar2 = (androidx.navigation.internal.m) cVar2.l.h;
                    JSONObject jSONObject3 = cVar2.a;
                    String strOptString2 = jSONObject3.optString("GroupNameMobile");
                    if (com.onetrust.otpublishers.headless.Internal.a.j(strOptString2)) {
                        strOptString2 = jSONObject3.optString("GroupName");
                    }
                    mVar2.g = strOptString2;
                    if (com.onetrust.otpublishers.headless.Internal.a.j((String) mVar2.b)) {
                        mVar2.b = preferenceCenterData.optString("PcTextColor");
                    }
                    androidx.navigation.internal.m mVar3 = (androidx.navigation.internal.m) cVar2.l.i;
                    JSONObject jSONObject4 = cVar2.a;
                    String strOptString3 = jSONObject4.optString("GroupNameMobile");
                    if (com.onetrust.otpublishers.headless.Internal.a.j(strOptString3)) {
                        strOptString3 = jSONObject4.optString("GroupName");
                    }
                    mVar3.g = strOptString3;
                    if (com.onetrust.otpublishers.headless.Internal.a.j((String) mVar3.b)) {
                        mVar3.b = preferenceCenterData.optString("PcTextColor");
                    }
                    androidx.navigation.internal.m mVar4 = (androidx.navigation.internal.m) cVar2.l.k;
                    String strOptString4 = preferenceCenterData.optString("BConsentText");
                    if (com.onetrust.otpublishers.headless.Internal.a.j((String) mVar4.b)) {
                        mVar4.b = preferenceCenterData.optString("PcTextColor");
                    }
                    mVar4.g = strOptString4;
                    androidx.navigation.internal.m mVar5 = (androidx.navigation.internal.m) cVar2.l.l;
                    String strOptString5 = preferenceCenterData.optString("BLegitInterestText");
                    if (com.onetrust.otpublishers.headless.Internal.a.j((String) mVar5.b)) {
                        mVar5.b = preferenceCenterData.optString("PcTextColor");
                    }
                    mVar5.g = strOptString5;
                    com.onetrust.otpublishers.headless.UI.mobiledatautils.c.b((com.quizlet.data.repository.user.e) cVar2.l.n, preferenceCenterData.optString("ThirdPartyCookieListText", "First Party Cookies"), preferenceCenterData);
                    com.onetrust.otpublishers.headless.UI.mobiledatautils.c.b((com.quizlet.data.repository.user.e) cVar2.l.o, preferenceCenterData.getString("VendorListText"), preferenceCenterData);
                    com.onetrust.otpublishers.headless.UI.mobiledatautils.c.b((com.quizlet.data.repository.user.e) cVar2.l.p, preferenceCenterData.optString("PCVendorFullLegalText", ""), preferenceCenterData);
                    ((androidx.camera.camera2.internal.compat.workaround.b) cVar2.l.q).b = preferenceCenterData.optString("PCenterBackText");
                    ((com.quizlet.data.repository.user.e) cVar2.l.p).e = preferenceCenterData.optString("PCPrivacyLinkActionAriaLabel");
                }
            } catch (JSONException e) {
                W.a("No Data found to initialize PC Detail Config, ", e, "PC Detail", 6);
            }
        }
        this.C1 = this.M1.a;
        com.onetrust.otpublishers.headless.Internal.Preferences.f fVar2 = null;
        if (this.L1 == null) {
            com.onetrust.otpublishers.headless.UI.mobiledatautils.b bVar2 = new com.onetrust.otpublishers.headless.UI.mobiledatautils.b();
            this.L1 = bVar2;
            if (!bVar2.j(iD, this.d1, this.e1)) {
                G();
                return null;
            }
        }
        com.onetrust.otpublishers.headless.UI.mobiledatautils.b bVar3 = this.L1;
        if (bVar3 != null) {
            this.y1 = bVar3.o;
        }
        com.onetrust.otpublishers.headless.UI.mobiledatautils.c cVar3 = this.M1;
        this.I1 = cVar3.l;
        this.K1 = cVar3.m;
        Context context2 = this.d1;
        SharedPreferences sharedPreferences = context2.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
        if (Q.a(context2)) {
            fVar2 = new com.onetrust.otpublishers.headless.Internal.Preferences.f(context2, sharedPreferences, sharedPreferences.getString("OT_ACTIVE_PROFILE_ID", ""));
            z = true;
        }
        if (z) {
            sharedPreferences = fVar2;
        }
        String string2 = sharedPreferences.getString("OT_VENDOR_COUNT_FOR_CATEGORIES", "");
        OTLogger.c("IAB2V2Flow", 3, "Getting vendorCountForCategoryString = " + string2);
        if (com.onetrust.otpublishers.headless.Internal.a.j(string2)) {
            jSONObject = new JSONObject();
        } else {
            try {
                jSONObject = new JSONObject(string2);
            } catch (JSONException e2) {
                Z.p("Error on getting vendor count for categories : ", e2, "OTSPUtils", 6);
            }
        }
        this.O1 = jSONObject;
        assistantMode.utils.studiableMetadata.b bVar4 = this.F1;
        Context context3 = this.d1;
        bVar4.getClass();
        View viewJ = assistantMode.utils.studiableMetadata.b.j(context3, layoutInflater, viewGroup, R.layout.ot_preference_center_details_fragment);
        this.o1 = (RelativeLayout) viewJ.findViewById(R.id.main_sub_layout);
        this.r = (TextView) viewJ.findViewById(R.id.parent_group_name);
        this.w = (TextView) viewJ.findViewById(R.id.parent_group_desc);
        this.v = (TextView) viewJ.findViewById(R.id.sub_group_name);
        this.x = (TextView) viewJ.findViewById(R.id.sub_group_desc);
        this.s1 = (FrameLayout) viewJ.findViewById(R.id.group_layout);
        this.n1 = (RelativeLayout) viewJ.findViewById(R.id.pc_details_main_layout);
        this.t = (TextView) viewJ.findViewById(R.id.tv_consent);
        this.u = (TextView) viewJ.findViewById(R.id.tv_legit_Int);
        this.g1 = (SwitchCompat) viewJ.findViewById(R.id.parent_group_consent_toggle);
        this.i1 = (SwitchCompat) viewJ.findViewById(R.id.consent_toggle);
        this.j1 = (SwitchCompat) viewJ.findViewById(R.id.legitInt_toggle);
        this.t1 = (ImageView) viewJ.findViewById(R.id.back_to_pc);
        this.y = (TextView) viewJ.findViewById(R.id.vendors_list_link);
        this.A = (TextView) viewJ.findViewById(R.id.view_legal_text);
        this.s = (TextView) viewJ.findViewById(R.id.parent_tv_consent);
        this.z = (TextView) viewJ.findViewById(R.id.parent_tv_legit_Int);
        this.h1 = (SwitchCompat) viewJ.findViewById(R.id.parent_group_li_toggle);
        this.k1 = (SwitchCompat) viewJ.findViewById(R.id.consent_toggle_non_iab);
        this.l1 = (SwitchCompat) viewJ.findViewById(R.id.parent_consent_toggle_non_iab);
        this.m1 = (RecyclerView) viewJ.findViewById(R.id.rv_pc_details);
        this.C = (TextView) viewJ.findViewById(R.id.alwaysActiveText);
        this.B = (TextView) viewJ.findViewById(R.id.alwaysActiveTextChild);
        this.X = (TextView) viewJ.findViewById(R.id.alwaysActiveText_non_iab);
        this.D = (TextView) viewJ.findViewById(R.id.vendors_list_link_below);
        this.E = (TextView) viewJ.findViewById(R.id.view_legal_text_below);
        this.G = (TextView) viewJ.findViewById(R.id.vendors_list_link_parent);
        this.H = (TextView) viewJ.findViewById(R.id.view_legal_text_parent);
        this.I = (TextView) viewJ.findViewById(R.id.view_legal_text_parent_below);
        this.J = (TextView) viewJ.findViewById(R.id.sdk_list_link);
        this.K = (TextView) viewJ.findViewById(R.id.sdk_list_link_child);
        this.V = (TextView) viewJ.findViewById(R.id.sdk_list_link_parent_below_combined);
        this.W = (TextView) viewJ.findViewById(R.id.sdk_list_link_child_below);
        this.L = (TextView) viewJ.findViewById(R.id.vendors_list_link_parent_below_combined);
        this.M = (TextView) viewJ.findViewById(R.id.view_legal_text_parent_below_combined);
        this.Y = (TextView) viewJ.findViewById(R.id.parent_alwaysActiveText_non_iab);
        this.u1 = (TextView) viewJ.findViewById(R.id.view_powered_by_logo);
        this.F = (TextView) viewJ.findViewById(R.id.view_iab_illustration);
        this.m1.setHasFixedSize(true);
        this.m1.setLayoutManager(new LinearLayoutManager(getActivity()));
        this.t1.setOnClickListener(this);
        this.y.setOnClickListener(this);
        this.A.setOnClickListener(this);
        this.E.setOnClickListener(this);
        this.F.setOnClickListener(this);
        this.D.setOnClickListener(this);
        this.G.setOnClickListener(this);
        this.H.setOnClickListener(this);
        this.L.setOnClickListener(this);
        this.M.setOnClickListener(this);
        this.I.setOnClickListener(this);
        this.J.setOnClickListener(this);
        this.K.setOnClickListener(this);
        this.V.setOnClickListener(this);
        this.W.setOnClickListener(this);
        com.google.mlkit.common.internal.model.a.f(this.d1, viewJ, "OTPCDetail");
        try {
            X();
        } catch (JSONException e3) {
            Z.p("error in populating views with data ", e3, "OneTrust", 6);
        }
        return viewJ;
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, androidx.fragment.app.Fragment
    public final void onDestroyView() {
        super.onDestroyView();
        this.x1 = null;
        this.f1 = null;
    }

    @Override // androidx.fragment.app.Fragment
    public final void onResume() throws Resources.NotFoundException {
        super.onResume();
        Y();
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t
    public final void p(int i) {
        if (i == 1) {
            G();
            com.onetrust.otpublishers.headless.UI.adapter.m mVar = this.f1;
            if (mVar != null) {
                mVar.p(i);
            }
        }
        if (i == 3) {
            com.google.firebase.perf.logging.b bVar = D.D;
            com.onetrust.otpublishers.headless.Internal.Event.a aVar = this.x1;
            OTConfiguration oTConfiguration = this.J1;
            bVar.getClass();
            D dA = com.google.firebase.perf.logging.b.a(aVar, oTConfiguration);
            this.v1 = dA;
            dA.R(this.e1);
        }
    }
}

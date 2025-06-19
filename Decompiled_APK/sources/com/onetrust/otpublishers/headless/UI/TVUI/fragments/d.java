package com.onetrust.otpublishers.headless.UI.TVUI.fragments;

import android.R;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.res.ColorStateList;
import android.graphics.Color;
import android.os.Bundle;
import android.view.KeyEvent;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.cardview.widget.CardView;
import androidx.fragment.app.Fragment;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3617f4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.Q;
import com.google.android.gms.internal.mlkit_vision_document_scanner.Y;
import com.google.android.gms.measurement.internal.Z;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.onetrust.otpublishers.headless.Public.Keys.OTFragmentTags;
import com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK;
import com.onetrust.otpublishers.headless.qrcode.OTQRCodeUtils;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Objects;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public class d extends Fragment implements com.onetrust.otpublishers.headless.UI.TVUI.adapter.j, View.OnKeyListener, View.OnFocusChangeListener {
    public com.onetrust.otpublishers.headless.UI.TVUI.datautils.c A;
    public CardView B;
    public CardView C;
    public CardView D;
    public CardView E;
    public CardView F;
    public LinearLayout G;
    public LinearLayout H;
    public LinearLayout I;
    public LinearLayout J;
    public LinearLayout K;
    public TextView L;
    public TextView M;
    public TextView V;
    public RelativeLayout W;
    public TextView X;
    public CheckBox Y;
    public CheckBox Z;
    public TextView a;
    public TextView b;
    public TextView c;
    public CheckBox c1;
    public TextView d;
    public CheckBox d1;
    public TextView e;
    public RecyclerView f;
    public Context g;
    public String g1;
    public LinearLayout h;
    public ImageView h1;
    public LinearLayout i;
    public LinearLayout i1;
    public TextView j;
    public TextView j1;
    public OTPublishersHeadlessSDK k;
    public View k1;
    public TextView l;
    public TextView m;
    public TextView n;
    public TextView o;
    public TextView p;
    public View q;
    public Button r;
    public Button s;
    public TextView t;
    public JSONObject u;
    public LinearLayout v;
    public com.onetrust.otpublishers.headless.Internal.Event.a w;
    public k x;
    public com.onetrust.otpublishers.headless.UI.TVUI.adapter.l y;
    public View z;
    public boolean e1 = true;
    public boolean f1 = true;

    public final void G(String str, String str2) {
        int[][] iArr = {new int[]{R.attr.state_checked}, new int[0]};
        int[] iArr2 = {Color.parseColor(str), Color.parseColor(str)};
        this.Y.setButtonTintList(new ColorStateList(iArr, iArr2));
        this.c1.setButtonTintList(new ColorStateList(iArr, iArr2));
        this.X.setTextColor(Color.parseColor(str));
        this.d.setTextColor(Color.parseColor(str));
        this.h.setBackgroundColor(Color.parseColor(str2));
        AbstractC3617f4.f(this.d, str);
    }

    public final void H(String str, boolean z) {
        com.onetrust.otpublishers.headless.Internal.Preferences.f fVar;
        boolean z2;
        if (this.u.optBoolean("IsIabPurpose")) {
            return;
        }
        Context contextRequireContext = requireContext();
        new JSONObject();
        SharedPreferences sharedPreferences = contextRequireContext.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
        if (Q.a(contextRequireContext)) {
            fVar = new com.onetrust.otpublishers.headless.Internal.Preferences.f(contextRequireContext, sharedPreferences, sharedPreferences.getString("OT_ACTIVE_PROFILE_ID", ""));
            z2 = true;
        } else {
            fVar = null;
            z2 = false;
        }
        if (z2) {
            sharedPreferences = fVar;
        }
        new com.onetrust.otpublishers.headless.Internal.Preferences.d(contextRequireContext);
        OTPublishersHeadlessSDK oTPublishersHeadlessSDK = this.k;
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
                oTPublishersHeadlessSDK.updateSDKConsentStatus(jSONArray.get(i).toString(), z);
            } catch (JSONException e2) {
                Z.p("Error while Updating consent of SDK ", e2, "SdkListHelper", 6);
            }
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:18:0x0051, code lost:
    
        r6.k.updatePurposeConsent(r0, true);
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void I(boolean r7) {
        /*
            r6 = this;
            org.json.JSONObject r0 = r6.u
            java.lang.String r1 = "CustomGroupId"
            java.lang.String r0 = r0.optString(r1)
            boolean r0 = com.onetrust.otpublishers.headless.Internal.a.j(r0)
            if (r0 != 0) goto L79
            org.json.JSONObject r0 = r6.u
            java.lang.String r0 = r0.optString(r1)
            r1 = 0
            r6.e1 = r1
            r2 = 1
            if (r7 != 0) goto L20
            com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK r7 = r6.k
            r7.updatePurposeConsent(r0, r1)
            goto L5f
        L20:
            com.onetrust.otpublishers.headless.UI.TVUI.datautils.c r7 = com.onetrust.otpublishers.headless.UI.TVUI.datautils.c.i()     // Catch: org.json.JSONException -> L4f
            com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK r3 = r6.k     // Catch: org.json.JSONException -> L4f
            org.json.JSONObject r7 = r7.c     // Catch: org.json.JSONException -> L4f
            org.json.JSONArray r4 = r7.names()     // Catch: org.json.JSONException -> L4f
            java.lang.String r4 = r4.toString()     // Catch: org.json.JSONException -> L4f
            boolean r4 = r4.contains(r0)     // Catch: org.json.JSONException -> L4f
            if (r4 == 0) goto L5f
            org.json.JSONArray r7 = r7.optJSONArray(r0)     // Catch: org.json.JSONException -> L4f
            r4 = r1
        L3b:
            int r5 = r7.length()     // Catch: org.json.JSONException -> L4f
            if (r4 >= r5) goto L51
            java.lang.String r5 = r7.getString(r4)     // Catch: org.json.JSONException -> L4f
            int r5 = r3.getPurposeConsentLocal(r5)     // Catch: org.json.JSONException -> L4f
            if (r5 != 0) goto L4c
            goto L5f
        L4c:
            int r4 = r4 + 1
            goto L3b
        L4f:
            r7 = move-exception
            goto L57
        L51:
            com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK r7 = r6.k     // Catch: org.json.JSONException -> L4f
            r7.updatePurposeConsent(r0, r2)     // Catch: org.json.JSONException -> L4f
            goto L5f
        L57:
            java.lang.String r3 = "error while updating parent category status on TV, err: "
            java.lang.String r4 = "OneTrust"
            r5 = 6
            com.google.android.gms.measurement.internal.Z.p(r3, r7, r4, r5)
        L5f:
            com.onetrust.otpublishers.headless.UI.TVUI.datautils.c r7 = r6.A
            boolean r7 = r7.p()
            if (r7 == 0) goto L76
            com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK r7 = r6.k
            int r7 = r7.getPurposeConsentLocal(r0)
            if (r7 != r2) goto L70
            r1 = r2
        L70:
            android.widget.CheckBox r7 = r6.Y
            r7.setChecked(r1)
            goto L79
        L76:
            r6.N()
        L79:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.UI.TVUI.fragments.d.I(boolean):void");
    }

    public final void J(boolean z, androidx.constraintlayout.motion.widget.n nVar, CardView cardView, LinearLayout linearLayout, TextView textView) {
        String strL;
        if (z) {
            cardView.setElevation(6.0f);
            if (com.onetrust.otpublishers.headless.Internal.a.j((String) nVar.l) || com.onetrust.otpublishers.headless.Internal.a.j((String) nVar.m)) {
                return;
            }
            linearLayout.setBackgroundColor(Color.parseColor((String) nVar.l));
            strL = (String) nVar.m;
        } else {
            cardView.setElevation(1.0f);
            linearLayout.setBackgroundColor(Color.parseColor(this.g1));
            strL = this.A.l();
        }
        textView.setTextColor(Color.parseColor(strL));
    }

    /* JADX WARN: Multi-variable type inference failed */
    public final void K() {
        String str;
        int i;
        int i2;
        JSONObject jSONObject;
        com.onetrust.otpublishers.headless.Internal.Preferences.f fVar;
        JSONObject jSONObject2;
        boolean z;
        com.onetrust.otpublishers.headless.Internal.Preferences.f fVar2;
        this.A = com.onetrust.otpublishers.headless.UI.TVUI.datautils.c.i();
        com.onetrust.otpublishers.headless.UI.TVUI.datautils.b bVarA = com.onetrust.otpublishers.headless.UI.TVUI.datautils.b.a();
        Context context = this.g;
        TextView textView = this.a;
        JSONObject jSONObject3 = this.u;
        assistantMode.utils.studiableMetadata.b.r(context, textView, jSONObject3.optString(com.onetrust.otpublishers.headless.Internal.a.j(jSONObject3.optString("GroupNameOTT")) ? "GroupName" : "GroupNameOTT"));
        this.d.setText(bVarA.b);
        this.e.setText(bVarA.c);
        TextView textView2 = this.j;
        com.onetrust.otpublishers.headless.UI.TVUI.datautils.c cVar = this.A;
        JSONObject jSONObject4 = this.u;
        cVar.getClass();
        String strM = com.onetrust.otpublishers.headless.UI.TVUI.datautils.c.m(jSONObject4);
        textView2.setVisibility((com.onetrust.otpublishers.headless.Internal.a.j(strM) || !cVar.e || "*".equals(strM)) ? 8 : 0);
        assistantMode.utils.studiableMetadata.b.r(this.g, this.j, com.onetrust.otpublishers.headless.UI.TVUI.datautils.c.m(this.u));
        this.L.setText((String) ((androidx.navigation.internal.m) this.A.j.E.b).g);
        this.M.setText(this.A.p);
        if (com.onetrust.otpublishers.headless.Internal.a.j(com.onetrust.otpublishers.headless.UI.TVUI.datautils.c.j(this.u))) {
            this.b.setVisibility(8);
        } else {
            assistantMode.utils.studiableMetadata.b.r(this.g, this.b, com.onetrust.otpublishers.headless.UI.TVUI.datautils.c.j(this.u));
        }
        com.onetrust.otpublishers.headless.UI.TVUI.datautils.c cVar2 = this.A;
        this.g1 = AbstractC3617f4.j(cVar2.a());
        String strL = cVar2.l();
        this.b.setTextColor(Color.parseColor(strL));
        this.a.setTextColor(Color.parseColor(strL));
        this.v.setBackgroundColor(Color.parseColor(cVar2.a()));
        this.z.setBackgroundColor(Color.parseColor(strL));
        this.c.setTextColor(Color.parseColor(strL));
        this.j.setTextColor(Color.parseColor(strL));
        J(false, cVar2.j.y, this.D, this.G, this.L);
        J(false, cVar2.j.y, this.E, this.H, this.M);
        G(strL, this.g1);
        L(strL, this.g1);
        this.B.setCardElevation(1.0f);
        this.C.setCardElevation(1.0f);
        N();
        if (this.u.optBoolean("IS_PARTNERS_LINK")) {
            this.B.setVisibility(8);
            this.C.setVisibility(8);
            this.J.setVisibility(8);
            this.K.setVisibility(0);
            this.r.setText(this.A.k);
            Context context2 = getContext();
            TextView textView3 = this.t;
            String str2 = this.A.m;
            if (str2 == null) {
                str2 = "";
            }
            assistantMode.utils.studiableMetadata.b.r(context2, textView3, str2);
            this.t.setTextColor(Color.parseColor(this.A.l()));
            Context context3 = getContext();
            SharedPreferences sharedPreferences = context3.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
            if (Z.r(Boolean.FALSE, Y.a(context3), "OT_ENABLE_MULTI_PROFILE")) {
                fVar2 = new com.onetrust.otpublishers.headless.Internal.Preferences.f(context3, sharedPreferences, sharedPreferences.getString("OT_ACTIVE_PROFILE_ID", ""));
                z = true;
            } else {
                z = false;
                fVar2 = null;
            }
            if (z) {
                sharedPreferences = fVar2;
            }
            if (sharedPreferences.getBoolean("OT_GOOGLE_VENDORS_ENABLED_STATE", false)) {
                this.s.setVisibility(0);
                this.s.setText(this.A.l);
            }
            AbstractC3617f4.m(this.r, this.A.j.y, false);
            AbstractC3617f4.m(this.s, this.A.j.y, false);
            if (com.onetrust.otpublishers.headless.Internal.a.j((String) this.A.j.y.g)) {
                this.r.setMinHeight(70);
                this.r.setMinimumHeight(70);
                this.s.setMinHeight(70);
                this.s.setMinimumHeight(70);
            } else {
                this.r.setMinHeight(0);
                this.r.setMinimumHeight(0);
                this.s.setMinHeight(0);
                this.s.setMinimumHeight(0);
                this.r.setPadding(15, 5, 15, 5);
                this.s.setPadding(15, 5, 15, 5);
            }
            str = "IsIabPurpose";
            i = 1;
        } else if (this.u.optBoolean("isAlertNotice")) {
            str = "IsIabPurpose";
            i = 1;
            this.B.setVisibility(8);
            this.C.setVisibility(8);
            com.onetrust.otpublishers.headless.UI.UIProperty.e eVar = this.A.j;
            if (Boolean.parseBoolean(eVar.I)) {
                TextView textView4 = this.l;
                androidx.navigation.internal.m mVar = eVar.m;
                textView4.setText((String) mVar.g);
                textView4.setTextColor(Color.parseColor(this.A.l()));
                textView4.setVisibility(mVar.c);
                TextView textView5 = this.m;
                androidx.navigation.internal.m mVar2 = eVar.n;
                textView5.setText((String) mVar2.g);
                textView5.setTextColor(Color.parseColor(this.A.l()));
                textView5.setVisibility(mVar2.c);
                TextView textView6 = this.n;
                androidx.navigation.internal.m mVar3 = eVar.o;
                textView6.setText((String) mVar3.g);
                textView6.setTextColor(Color.parseColor(this.A.l()));
                textView6.setVisibility(mVar3.c);
                TextView textView7 = this.o;
                androidx.navigation.internal.m mVar4 = eVar.p;
                textView7.setText((String) mVar4.g);
                textView7.setTextColor(Color.parseColor(this.A.l()));
                textView7.setVisibility(mVar4.c);
                TextView textView8 = this.p;
                androidx.navigation.internal.m mVar5 = eVar.r;
                textView8.setText((String) mVar5.g);
                textView8.setTextColor(Color.parseColor(this.A.l()));
                textView8.setVisibility(mVar5.c);
                this.q.setBackgroundColor(Color.parseColor(this.A.l()));
            } else {
                this.J.setVisibility(8);
            }
            com.quizlet.data.repository.user.e eVar2 = this.A.j.D;
            String str3 = (String) eVar2.c;
            androidx.navigation.internal.m mVar6 = (androidx.navigation.internal.m) eVar2.b;
            String str4 = (String) mVar6.g;
            boolean zA = mVar6.a();
            if (!com.onetrust.otpublishers.headless.Internal.a.j(str3) && zA && com.google.mlkit.common.internal.model.a.n(getActivity(), OTFragmentTags.OT_PREFERENCE_CENTER_DETAILS_FRAGMENT_TAG)) {
                this.i1.setVisibility(0);
                try {
                    OTQRCodeUtils.b(str3, getActivity(), this.A.a(), this.A.l(), this.h1, false);
                    this.j1.setText(str4);
                    this.j1.setTextColor(Color.parseColor(this.A.l()));
                    this.k1.setBackgroundColor(Color.parseColor(this.A.l()));
                } catch (Exception e) {
                    OTLogger.c("OneTrust", 6, "Exception while rendering QR code," + e);
                }
            } else {
                this.i1.setVisibility(8);
            }
        } else {
            this.J.setVisibility(8);
            this.B.setVisibility(this.A.o(this.u));
            this.C.setVisibility(this.A.o(this.u));
            if (this.u.optBoolean("IsIabPurpose")) {
                this.B.setVisibility(this.u.optBoolean("HasConsentOptOut") ? 0 : 8);
                this.C.setVisibility(this.u.optBoolean("HasLegIntOptOut") ? 0 : 8);
            }
            CardView cardView = this.F;
            com.onetrust.otpublishers.headless.UI.TVUI.datautils.c cVar3 = this.A;
            JSONObject jSONObject5 = this.u;
            cVar3.getClass();
            cardView.setVisibility((jSONObject5.optBoolean("ShowSDKListLink") && cVar3.n && com.onetrust.otpublishers.headless.UI.TVUI.datautils.c.h(jSONObject5)) ? 0 : 8);
            this.V.setText((String) ((androidx.navigation.internal.m) this.A.j.F.b).g);
            str = "IsIabPurpose";
            i = 1;
            J(false, this.A.j.y, this.F, this.I, this.V);
        }
        this.D.setVisibility(this.u.optBoolean(str) ? 0 : 8);
        this.E.setVisibility((this.u.optBoolean(str) && assistantMode.utils.studiableMetadata.b.B(this.u)) ? 0 : 8);
        if (!this.u.optString("Status").contains("always")) {
            if (this.A.p() && !this.u.optBoolean("isAlertNotice")) {
                OTLogger.c("TVPCDetail", 3, "Showing Consent Toggle UI");
                this.c1.setVisibility(8);
                this.d1.setVisibility(8);
                this.d.setText(this.A.b(!this.u.optBoolean(str)));
                this.e.setText(this.A.h);
                int purposeLegitInterestLocal = this.k.getPurposeLegitInterestLocal(this.u.optString("CustomGroupId"));
                int i3 = (!this.A.i || purposeLegitInterestLocal <= -1) ? 8 : 0;
                this.C.setVisibility(i3);
                this.Z.setVisibility(i3);
                this.Y.setVisibility(0);
                if (i3 == 0) {
                    i2 = i;
                    this.Z.setChecked(purposeLegitInterestLocal == i2 ? i2 : 0);
                } else {
                    i2 = i;
                }
                this.Y.setChecked(this.k.getPurposeConsentLocal(this.u.optString("CustomGroupId")) == i2 ? i2 : 0);
            }
            this.c.setVisibility(8);
            this.z.setVisibility(this.D.getVisibility());
            jSONObject = this.u;
            if (jSONObject.has("SubGroups") || !jSONObject.optBoolean("ShowSubgroup")) {
            }
            Context context4 = this.g;
            SharedPreferences sharedPreferences2 = context4.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
            if (Q.a(context4)) {
                fVar = new com.onetrust.otpublishers.headless.Internal.Preferences.f(context4, sharedPreferences2, sharedPreferences2.getString("OT_ACTIVE_PROFILE_ID", ""));
            } else {
                i2 = 0;
                fVar = null;
            }
            if (i2 != 0) {
                sharedPreferences2 = fVar;
            }
            String string = sharedPreferences2.getString("OT_VENDOR_COUNT_FOR_CATEGORIES", "");
            OTLogger.c("IAB2V2Flow", 3, "Getting vendorCountForCategoryString = " + string);
            if (com.onetrust.otpublishers.headless.Internal.a.j(string)) {
                jSONObject2 = new JSONObject();
            } else {
                try {
                    jSONObject2 = new JSONObject(string);
                } catch (JSONException e2) {
                    Z.p("Error on getting vendor count for categories : ", e2, "OTSPUtils", 6);
                }
            }
            JSONObject jSONObject6 = jSONObject2;
            JSONArray jSONArrayOptJSONArray = this.u.optJSONArray("SubGroups");
            Objects.requireNonNull(jSONArrayOptJSONArray);
            com.onetrust.otpublishers.headless.UI.TVUI.adapter.l lVar = new com.onetrust.otpublishers.headless.UI.TVUI.adapter.l(jSONArrayOptJSONArray, this.g, this.k, this, jSONObject6);
            this.y = lVar;
            this.f.setAdapter(lVar);
            this.c.setText(bVarA.d);
            this.c.setVisibility(0);
            this.z.setVisibility(0);
            return;
        }
        if (!this.u.optBoolean("isAlertNotice")) {
            this.B.setVisibility(0);
        }
        com.onetrust.otpublishers.headless.UI.TVUI.datautils.c cVar4 = this.A;
        String str5 = (String) cVar4.j.u.g;
        if (str5 == null) {
            str5 = cVar4.b;
        }
        if (cVar4.p()) {
            this.d.setText(this.A.b(!this.u.optBoolean(str)));
            this.X.setVisibility(0);
            this.X.setText(str5);
        } else {
            this.d.setText(str5);
            N();
        }
        this.c1.setVisibility(8);
        if (com.onetrust.otpublishers.headless.Internal.a.j(str5)) {
            this.B.setVisibility(8);
        }
        i2 = i;
        this.c.setVisibility(8);
        this.z.setVisibility(this.D.getVisibility());
        jSONObject = this.u;
        if (jSONObject.has("SubGroups")) {
        }
    }

    public final void L(String str, String str2) {
        int[][] iArr = {new int[]{R.attr.state_checked}, new int[0]};
        int[] iArr2 = {Color.parseColor(str), Color.parseColor(str)};
        this.Z.setButtonTintList(new ColorStateList(iArr, iArr2));
        this.d1.setButtonTintList(new ColorStateList(iArr, iArr2));
        this.e.setTextColor(Color.parseColor(str));
        this.i.setBackgroundColor(Color.parseColor(str2));
        AbstractC3617f4.f(this.e, str);
    }

    /* JADX WARN: Code restructure failed: missing block: B:18:0x0051, code lost:
    
        r6.k.updatePurposeLegitInterest(r0, true);
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void M(boolean r7) throws org.json.JSONException {
        /*
            r6 = this;
            org.json.JSONObject r0 = r6.u
            java.lang.String r1 = "CustomGroupId"
            java.lang.String r0 = r0.optString(r1)
            boolean r0 = com.onetrust.otpublishers.headless.Internal.a.j(r0)
            if (r0 != 0) goto L6d
            org.json.JSONObject r0 = r6.u
            java.lang.String r0 = r0.optString(r1)
            r1 = 0
            r6.f1 = r1
            r2 = 1
            if (r7 != 0) goto L20
            com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK r7 = r6.k
            r7.updatePurposeLegitInterest(r0, r1)
            goto L5f
        L20:
            com.onetrust.otpublishers.headless.UI.TVUI.datautils.c r7 = com.onetrust.otpublishers.headless.UI.TVUI.datautils.c.i()     // Catch: org.json.JSONException -> L4f
            com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK r3 = r6.k     // Catch: org.json.JSONException -> L4f
            org.json.JSONObject r7 = r7.c     // Catch: org.json.JSONException -> L4f
            org.json.JSONArray r4 = r7.names()     // Catch: org.json.JSONException -> L4f
            java.lang.String r4 = r4.toString()     // Catch: org.json.JSONException -> L4f
            boolean r4 = r4.contains(r0)     // Catch: org.json.JSONException -> L4f
            if (r4 == 0) goto L5f
            org.json.JSONArray r7 = r7.optJSONArray(r0)     // Catch: org.json.JSONException -> L4f
            r4 = r1
        L3b:
            int r5 = r7.length()     // Catch: org.json.JSONException -> L4f
            if (r4 >= r5) goto L51
            java.lang.String r5 = r7.getString(r4)     // Catch: org.json.JSONException -> L4f
            int r5 = r3.getPurposeLegitInterestLocal(r5)     // Catch: org.json.JSONException -> L4f
            if (r5 != 0) goto L4c
            goto L5f
        L4c:
            int r4 = r4 + 1
            goto L3b
        L4f:
            r7 = move-exception
            goto L57
        L51:
            com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK r7 = r6.k     // Catch: org.json.JSONException -> L4f
            r7.updatePurposeLegitInterest(r0, r2)     // Catch: org.json.JSONException -> L4f
            goto L5f
        L57:
            java.lang.String r3 = "error while updating parent LI status on TV, err: "
            java.lang.String r4 = "OneTrust"
            r5 = 6
            com.google.android.gms.measurement.internal.Z.p(r3, r7, r4, r5)
        L5f:
            android.widget.CheckBox r7 = r6.Z
            com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK r3 = r6.k
            int r0 = r3.getPurposeLegitInterestLocal(r0)
            if (r0 != r2) goto L6a
            r1 = r2
        L6a:
            r7.setChecked(r1)
        L6d:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.UI.TVUI.fragments.d.M(boolean):void");
    }

    public final void N() {
        CheckBox checkBox;
        if (this.k.getPurposeConsentLocal(this.u.optString("CustomGroupId")) == 1) {
            this.c1.setChecked(true);
            checkBox = this.d1;
        } else {
            this.d1.setChecked(true);
            checkBox = this.c1;
        }
        checkBox.setChecked(false);
    }

    public final void O(boolean z) {
        String strOptString = this.u.optString("CustomGroupId");
        this.k.updatePurposeConsent(strOptString, z);
        androidx.compose.foundation.lazy.grid.m mVar = new androidx.compose.foundation.lazy.grid.m(7, 4);
        mVar.c = strOptString;
        mVar.b = z ? 1 : 0;
        com.onetrust.otpublishers.headless.Internal.Event.a aVar = this.w;
        if (aVar != null) {
            aVar.a(mVar);
        } else {
            OTLogger.c("OneTrust", 6, "Error on sending UI events, listener set was found to be null.This could be because the activity has been recreated. \n Please set listener to get UI event callbacks.");
        }
        H(strOptString, z);
        if (this.u.has("SubGroups") && com.onetrust.otpublishers.headless.Internal.a.j(this.u.optString("Parent")) && this.e1) {
            OTPublishersHeadlessSDK oTPublishersHeadlessSDK = this.k;
            JSONObject jSONObject = this.u;
            for (int i = 0; i < jSONObject.getJSONArray("SubGroups").length(); i++) {
                try {
                    String strOptString2 = jSONObject.getJSONArray("SubGroups").getJSONObject(i).optString("CustomGroupId");
                    oTPublishersHeadlessSDK.updatePurposeConsent(strOptString2, z);
                    H(strOptString2, z);
                } catch (Exception e) {
                    Z.n("error while updating subgroup status on TV, err : ", e, "OneTrust", 6);
                }
            }
        }
        com.onetrust.otpublishers.headless.UI.TVUI.adapter.l lVar = this.y;
        if (lVar != null) {
            lVar.notifyDataSetChanged();
        }
        this.e1 = true;
    }

    @Override // com.onetrust.otpublishers.headless.UI.TVUI.adapter.j
    public final void a() {
        this.x.p(24);
    }

    @Override // androidx.fragment.app.Fragment
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        this.g = getContext();
    }

    @Override // androidx.fragment.app.Fragment
    public final View onCreateView(LayoutInflater layoutInflater, ViewGroup viewGroup, Bundle bundle) {
        Context context = this.g;
        if (com.onetrust.otpublishers.headless.Internal.a.o(context)) {
            layoutInflater = layoutInflater.cloneInContext(new androidx.appcompat.view.d(context, com.quizlet.quizletandroid.R.style.Theme_AppCompat_Light_NoActionBar));
        }
        View viewInflate = layoutInflater.inflate(com.quizlet.quizletandroid.R.layout.ot_pc_groupdetail_tv, viewGroup, false);
        this.a = (TextView) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.tv_category_title);
        this.b = (TextView) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.tv_category_desc);
        this.h = (LinearLayout) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.group_status_on);
        this.i = (LinearLayout) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.group_status_off);
        this.t = (TextView) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.tv_vl_desc);
        this.f = (RecyclerView) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.tv_subgroup_list);
        this.c = (TextView) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.subgroup_list_title);
        this.z = viewInflate.findViewById(com.quizlet.quizletandroid.R.id.ot_grp_dtl_sg_div);
        this.v = (LinearLayout) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.tv_grp_detail_lyt);
        this.B = (CardView) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.tv_sg_card_on);
        this.C = (CardView) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.tv_sg_card_off);
        this.c1 = (CheckBox) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.tv_consent_on_cb);
        this.d1 = (CheckBox) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.tv_consent_off_cb);
        this.f.setHasFixedSize(true);
        this.f.setLayoutManager(new LinearLayoutManager(getActivity()));
        this.B.setOnKeyListener(this);
        this.C.setOnKeyListener(this);
        this.B.setOnFocusChangeListener(this);
        this.C.setOnFocusChangeListener(this);
        this.d = (TextView) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.group_status_on_tv);
        this.e = (TextView) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.group_status_off_tv);
        this.j = (TextView) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.ot_iab_legal_desc_tv);
        this.X = (TextView) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.always_active_status_iab);
        this.Y = (CheckBox) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.tv_consent_cb);
        this.Z = (CheckBox) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.tv_li_cb);
        this.J = (LinearLayout) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.tv_dsid_layout);
        this.l = (TextView) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.tv_dsid_title);
        this.m = (TextView) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.tv_dsid);
        this.n = (TextView) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.tv_timestamp_title);
        this.o = (TextView) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.tv_timestamp);
        this.p = (TextView) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.tv_dsid_description);
        this.q = viewInflate.findViewById(com.quizlet.quizletandroid.R.id.tv_dsid_divider);
        this.K = (LinearLayout) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.tv_partners_layout);
        this.r = (Button) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.tv_btn_iab_vendor);
        this.s = (Button) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.tv_btn_google_vendor);
        this.Z.setOnCheckedChangeListener(new com.google.android.material.chip.a(this, 2));
        this.D = (CardView) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.card_list_of_partners);
        this.E = (CardView) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.card_list_of_policy_link);
        this.G = (LinearLayout) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.list_of_partners_lyt);
        this.H = (LinearLayout) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.list_of_policy_link_layout);
        this.L = (TextView) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.list_of_partners_tv);
        this.M = (TextView) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.list_of_policy_link_tv);
        this.F = (CardView) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.card_list_of_sdks);
        this.I = (LinearLayout) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.list_of_sdks_lyt);
        this.V = (TextView) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.list_of_sdks_tv);
        this.W = (RelativeLayout) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.ot_tv_pc_detail_parent_lyt);
        this.D.setOnKeyListener(this);
        this.D.setOnFocusChangeListener(this);
        this.E.setOnKeyListener(this);
        this.E.setOnFocusChangeListener(this);
        this.F.setOnKeyListener(this);
        this.F.setOnFocusChangeListener(this);
        this.j.setOnKeyListener(this);
        this.b.setOnKeyListener(this);
        this.a.setOnKeyListener(this);
        this.a.setOnFocusChangeListener(this);
        this.r.setOnKeyListener(this);
        this.r.setOnFocusChangeListener(this);
        this.s.setOnFocusChangeListener(this);
        this.s.setOnKeyListener(this);
        this.t.setOnKeyListener(this);
        this.t.setOnFocusChangeListener(this);
        this.i1 = (LinearLayout) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.tv_qr_code);
        this.h1 = (ImageView) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.qrcode_img_tv);
        this.j1 = (TextView) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.tv_qr_code_text);
        this.k1 = viewInflate.findViewById(com.quizlet.quizletandroid.R.id.ot_qr_code_tv_div);
        this.h1.setOnKeyListener(this);
        this.j1.setOnKeyListener(this);
        K();
        com.onetrust.otpublishers.headless.UI.Helper.c cVar = this.A.r;
        if (cVar.p == 8 && cVar.t == 8 && cVar.u == 8) {
            this.a.setNextFocusUpId(com.quizlet.quizletandroid.R.id.tv_category_title);
        }
        return viewInflate;
    }

    @Override // android.view.View.OnFocusChangeListener
    public final void onFocusChange(View view, boolean z) {
        d dVar;
        boolean z2;
        if (view.getId() == com.quizlet.quizletandroid.R.id.tv_sg_card_on) {
            if (z) {
                androidx.constraintlayout.motion.widget.n nVar = this.A.j.y;
                G((String) nVar.m, (String) nVar.l);
                this.B.setCardElevation(6.0f);
            } else {
                G(this.A.l(), this.g1);
                this.B.setCardElevation(1.0f);
            }
        }
        if (view.getId() == com.quizlet.quizletandroid.R.id.tv_sg_card_off) {
            if (z) {
                androidx.constraintlayout.motion.widget.n nVar2 = this.A.j.y;
                L((String) nVar2.m, (String) nVar2.l);
                this.C.setCardElevation(6.0f);
            } else {
                L(this.A.l(), this.g1);
                this.C.setCardElevation(1.0f);
            }
        }
        if (view.getId() == com.quizlet.quizletandroid.R.id.card_list_of_partners) {
            J(z, this.A.j.y, this.D, this.G, this.L);
            dVar = this;
            z2 = z;
        } else {
            dVar = this;
            z2 = z;
        }
        if (view.getId() == com.quizlet.quizletandroid.R.id.card_list_of_policy_link) {
            dVar.J(z2, dVar.A.j.y, dVar.E, dVar.H, dVar.M);
        }
        if (view.getId() == com.quizlet.quizletandroid.R.id.card_list_of_sdks) {
            dVar.J(z2, dVar.A.j.y, dVar.F, dVar.I, dVar.V);
        }
        if (view.getId() == com.quizlet.quizletandroid.R.id.tv_btn_google_vendor) {
            AbstractC3617f4.k(dVar.s, dVar.A.j.y, z2);
        }
        if (view.getId() == com.quizlet.quizletandroid.R.id.tv_btn_iab_vendor) {
            AbstractC3617f4.k(dVar.r, dVar.A.j.y, z2);
        }
    }

    @Override // android.view.View.OnKeyListener
    public final boolean onKey(View view, int i, KeyEvent keyEvent) {
        if (this.A.p()) {
            if (view.getId() == com.quizlet.quizletandroid.R.id.tv_sg_card_on && AbstractC3617f4.a(i, keyEvent) == 21) {
                boolean z = !this.Y.isChecked();
                this.Y.setChecked(z);
                O(z);
            } else if (view.getId() == com.quizlet.quizletandroid.R.id.tv_sg_card_off && AbstractC3617f4.a(i, keyEvent) == 21) {
                this.Z.setChecked(!r0.isChecked());
            }
        } else if (view.getId() == com.quizlet.quizletandroid.R.id.tv_sg_card_on && AbstractC3617f4.a(i, keyEvent) == 21) {
            if (!this.c1.isChecked()) {
                O(true);
                this.c1.setChecked(true);
                this.d1.setChecked(false);
            }
        } else if (view.getId() == com.quizlet.quizletandroid.R.id.tv_sg_card_off && AbstractC3617f4.a(i, keyEvent) == 21 && !this.d1.isChecked()) {
            O(false);
            this.c1.setChecked(false);
            this.d1.setChecked(true);
        }
        JSONArray jSONArrayOptJSONArray = null;
        if (view.getId() == com.quizlet.quizletandroid.R.id.card_list_of_partners && AbstractC3617f4.a(i, keyEvent) == 21) {
            HashMap map = new HashMap();
            if (!this.u.optString("Type").equals("IAB2_STACK") && !this.u.optString("Type").equals("IAB2V2_STACK")) {
                map.put(this.u.optString("CustomGroupId"), this.u.optString("Type"));
            }
            JSONObject jSONObject = this.u;
            JSONArray jSONArrayOptJSONArray2 = (jSONObject.optJSONArray("SubGroups") == null || jSONObject.optJSONArray("SubGroups").length() <= 0) ? null : jSONObject.optJSONArray("SubGroups");
            if (jSONArrayOptJSONArray2 != null) {
                for (int i2 = 0; i2 < jSONArrayOptJSONArray2.length(); i2++) {
                    JSONObject jSONObjectOptJSONObject = jSONArrayOptJSONArray2.optJSONObject(i2);
                    if (jSONObjectOptJSONObject.optBoolean("IsIabPurpose")) {
                        map.put(jSONObjectOptJSONObject.optString("CustomGroupId"), jSONObjectOptJSONObject.optString("Type"));
                    }
                }
            }
            g gVar = this.x.c;
            gVar.y = 4;
            a aVar = gVar.z;
            if (aVar != null && aVar.getArguments() != null) {
                gVar.z.getArguments().putInt("OT_TV_FOCUSED_BTN", 1);
            }
            gVar.Q(map, true, false);
        }
        if (view.getId() == com.quizlet.quizletandroid.R.id.card_list_of_policy_link && AbstractC3617f4.a(i, keyEvent) == 21) {
            this.x.I(this.u, false, true);
        }
        if (i == 4 && keyEvent.getAction() == 1) {
            this.x.p(1);
        }
        if (AbstractC3617f4.a(i, keyEvent) == 24 || (view.getId() == com.quizlet.quizletandroid.R.id.qrcode_img_tv && AbstractC3617f4.a(i, keyEvent) == 24)) {
            this.x.p(24);
            return true;
        }
        if (view.getId() == com.quizlet.quizletandroid.R.id.ot_iab_legal_desc_tv && AbstractC3617f4.a(i, keyEvent) == 24) {
            this.x.p(24);
        }
        if (view.getId() == com.quizlet.quizletandroid.R.id.tv_category_desc && AbstractC3617f4.a(i, keyEvent) == 24) {
            this.x.p(24);
        }
        if (view.getId() == com.quizlet.quizletandroid.R.id.tv_category_title && AbstractC3617f4.a(i, keyEvent) == 24) {
            this.x.p(24);
        }
        if (view.getId() == com.quizlet.quizletandroid.R.id.tv_btn_google_vendor && AbstractC3617f4.a(i, keyEvent) == 21) {
            this.x.p(18);
        }
        if (view.getId() == com.quizlet.quizletandroid.R.id.tv_btn_iab_vendor && AbstractC3617f4.a(i, keyEvent) == 21) {
            this.x.p(17);
        }
        if (view.getId() == com.quizlet.quizletandroid.R.id.card_list_of_sdks && AbstractC3617f4.a(i, keyEvent) == 21) {
            ArrayList arrayList = new ArrayList();
            if (!retrofit2.adapter.rxjava3.d.l(this.u.optJSONArray("FirstPartyCookies"))) {
                arrayList.add(this.u.optString("CustomGroupId"));
            }
            JSONObject jSONObject2 = this.u;
            if (jSONObject2.optJSONArray("SubGroups") != null && jSONObject2.optJSONArray("SubGroups").length() > 0) {
                jSONArrayOptJSONArray = jSONObject2.optJSONArray("SubGroups");
            }
            if (jSONArrayOptJSONArray != null) {
                for (int i3 = 0; i3 < jSONArrayOptJSONArray.length(); i3++) {
                    JSONObject jSONObjectOptJSONObject2 = jSONArrayOptJSONArray.optJSONObject(i3);
                    if (!jSONObjectOptJSONObject2.optBoolean("IsIabPurpose") && jSONObjectOptJSONObject2.optBoolean("ShowSDKListLink")) {
                        arrayList.add(jSONObjectOptJSONObject2.optString("CustomGroupId"));
                    }
                }
            }
            this.x.H(arrayList);
        }
        return false;
    }

    @Override // com.onetrust.otpublishers.headless.UI.TVUI.adapter.j
    public final void a(JSONObject jSONObject) {
        this.x.I(jSONObject, true, false);
    }
}

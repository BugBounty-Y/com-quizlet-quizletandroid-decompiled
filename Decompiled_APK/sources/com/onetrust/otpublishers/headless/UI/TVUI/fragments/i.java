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
import android.widget.CompoundButton;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.cardview.widget.CardView;
import androidx.fragment.app.Fragment;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3617f4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.Q;
import com.google.android.gms.measurement.internal.Z;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Objects;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public class i extends Fragment implements com.onetrust.otpublishers.headless.UI.TVUI.adapter.j, View.OnKeyListener, View.OnFocusChangeListener {
    public ImageView A;
    public int B;
    public CardView C;
    public CardView D;
    public LinearLayout E;
    public LinearLayout F;
    public TextView G;
    public TextView H;
    public CardView I;
    public LinearLayout J;
    public TextView K;
    public String L;
    public TextView a;
    public TextView b;
    public TextView c;
    public TextView d;
    public TextView e;
    public RecyclerView f;
    public Context g;
    public LinearLayout h;
    public LinearLayout i;
    public TextView j;
    public OTPublishersHeadlessSDK k;
    public JSONObject l;
    public LinearLayout m;
    public com.onetrust.otpublishers.headless.Internal.Event.a n;
    public k o;
    public boolean p;
    public com.onetrust.otpublishers.headless.UI.TVUI.adapter.l q;
    public View r;
    public com.onetrust.otpublishers.headless.UI.TVUI.datautils.c s;
    public CardView t;
    public CardView u;
    public TextView v;
    public CheckBox w;
    public CheckBox x;
    public CheckBox y;
    public CheckBox z;

    public final void G(String str, String str2) {
        int[][] iArr = {new int[]{R.attr.state_checked}, new int[0]};
        int[] iArr2 = {Color.parseColor(str), Color.parseColor(str)};
        this.w.setButtonTintList(new ColorStateList(iArr, iArr2));
        this.y.setButtonTintList(new ColorStateList(iArr, iArr2));
        this.v.setTextColor(Color.parseColor(str));
        this.d.setTextColor(Color.parseColor(str));
        this.h.setBackgroundColor(Color.parseColor(str2));
        AbstractC3617f4.f(this.d, str);
    }

    public final void H(boolean z) {
        com.onetrust.otpublishers.headless.Internal.Preferences.f fVar;
        boolean z2;
        String strOptString = this.l.optString("CustomGroupId");
        androidx.compose.foundation.lazy.grid.m mVar = new androidx.compose.foundation.lazy.grid.m(7, 4);
        mVar.c = strOptString;
        mVar.b = z ? 1 : 0;
        com.onetrust.otpublishers.headless.Internal.Event.a aVar = this.n;
        if (aVar != null) {
            aVar.a(mVar);
        } else {
            OTLogger.c("OneTrust", 6, "Error on sending UI events, listener set was found to be null.This could be because the activity has been recreated. \n Please set listener to get UI event callbacks.");
        }
        this.k.updatePurposeConsent(strOptString, z);
        if (this.l.optBoolean("IsIabPurpose")) {
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
                if (jSONObject.has(strOptString)) {
                    jSONArray = new JSONArray(jSONObject.get(strOptString).toString());
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

    public final void I(boolean z, androidx.constraintlayout.motion.widget.n nVar, CardView cardView, LinearLayout linearLayout, TextView textView) {
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
            linearLayout.setBackgroundColor(Color.parseColor(this.L));
            strL = this.s.l();
        }
        textView.setTextColor(Color.parseColor(strL));
    }

    public final void J() {
        ImageView imageView;
        int i;
        com.onetrust.otpublishers.headless.Internal.Preferences.f fVar;
        JSONObject jSONObject;
        this.s = com.onetrust.otpublishers.headless.UI.TVUI.datautils.c.i();
        com.onetrust.otpublishers.headless.UI.TVUI.datautils.b bVarA = com.onetrust.otpublishers.headless.UI.TVUI.datautils.b.a();
        Context context = this.g;
        TextView textView = this.a;
        JSONObject jSONObject2 = this.l;
        assistantMode.utils.studiableMetadata.b.r(context, textView, jSONObject2.optString(com.onetrust.otpublishers.headless.Internal.a.j(jSONObject2.optString("GroupNameOTT")) ? "GroupName" : "GroupNameOTT"));
        this.d.setText(bVarA.b);
        this.e.setText(bVarA.c);
        TextView textView2 = this.j;
        com.onetrust.otpublishers.headless.UI.TVUI.datautils.c cVar = this.s;
        JSONObject jSONObject3 = this.l;
        cVar.getClass();
        String strM = com.onetrust.otpublishers.headless.UI.TVUI.datautils.c.m(jSONObject3);
        textView2.setVisibility((com.onetrust.otpublishers.headless.Internal.a.j(strM) || !cVar.e || "*".equals(strM)) ? 8 : 0);
        assistantMode.utils.studiableMetadata.b.r(this.g, this.j, com.onetrust.otpublishers.headless.UI.TVUI.datautils.c.m(this.l));
        this.G.setText((String) ((androidx.navigation.internal.m) this.s.j.E.b).g);
        this.H.setText(this.s.p);
        this.A.setVisibility(0);
        if (com.onetrust.otpublishers.headless.Internal.a.j(com.onetrust.otpublishers.headless.UI.TVUI.datautils.c.j(this.l))) {
            this.b.setVisibility(8);
        } else {
            assistantMode.utils.studiableMetadata.b.r(this.g, this.b, com.onetrust.otpublishers.headless.UI.TVUI.datautils.c.j(this.l));
        }
        com.onetrust.otpublishers.headless.UI.TVUI.datautils.c cVar2 = this.s;
        this.L = AbstractC3617f4.j(cVar2.a());
        String strL = cVar2.l();
        this.b.setTextColor(Color.parseColor(strL));
        this.a.setTextColor(Color.parseColor(strL));
        this.m.setBackgroundColor(Color.parseColor(cVar2.a()));
        this.r.setBackgroundColor(Color.parseColor(strL));
        this.c.setTextColor(Color.parseColor(strL));
        this.j.setTextColor(Color.parseColor(strL));
        I(false, cVar2.j.y, this.C, this.E, this.G);
        I(false, cVar2.j.y, this.D, this.F, this.H);
        G(strL, this.L);
        K(strL, this.L);
        this.t.setCardElevation(1.0f);
        this.u.setCardElevation(1.0f);
        AbstractC3617f4.i(false, cVar2.j.y, this.A);
        boolean z = true;
        (this.k.getPurposeConsentLocal(this.l.optString("CustomGroupId")) == 1 ? this.y : this.z).setChecked(true);
        this.t.setVisibility(this.s.o(this.l));
        this.u.setVisibility(this.s.o(this.l));
        if (this.l.optBoolean("IsIabPurpose")) {
            this.t.setVisibility(this.l.optBoolean("HasConsentOptOut") ? 0 : 8);
            this.u.setVisibility(this.l.optBoolean("HasLegIntOptOut") ? 0 : 8);
        }
        if (this.t.getVisibility() == 0) {
            imageView = this.A;
            i = com.quizlet.quizletandroid.R.id.tv_sg_card_on;
        } else {
            imageView = this.A;
            i = com.quizlet.quizletandroid.R.id.tv_category_desc;
        }
        imageView.setNextFocusDownId(i);
        this.C.setVisibility(this.l.optBoolean("IsIabPurpose") ? 0 : 8);
        this.D.setVisibility((this.l.optBoolean("IsIabPurpose") && assistantMode.utils.studiableMetadata.b.B(this.l)) ? 0 : 8);
        CardView cardView = this.I;
        com.onetrust.otpublishers.headless.UI.TVUI.datautils.c cVar3 = this.s;
        JSONObject jSONObject4 = this.l;
        cVar3.getClass();
        cardView.setVisibility((jSONObject4.optBoolean("ShowSDKListLink") && cVar3.n && com.onetrust.otpublishers.headless.UI.TVUI.datautils.c.h(jSONObject4)) ? 0 : 8);
        this.K.setText((String) ((androidx.navigation.internal.m) this.s.j.F.b).g);
        I(false, this.s.j.y, this.I, this.J, this.K);
        if (this.l.optString("Status").contains("always")) {
            if (!this.l.optBoolean("isAlertNotice")) {
                this.t.setVisibility(0);
            }
            com.onetrust.otpublishers.headless.UI.TVUI.datautils.c cVar4 = this.s;
            String str = (String) cVar4.j.u.g;
            if (str == null) {
                str = cVar4.b;
            }
            if (cVar4.p()) {
                this.d.setText(this.s.b(!this.l.optBoolean("IsIabPurpose")));
                this.v.setVisibility(0);
                this.v.setText(str);
            } else {
                this.d.setText(str);
                (this.k.getPurposeConsentLocal(this.l.optString("CustomGroupId")) == 1 ? this.y : this.z).setChecked(true);
            }
            this.y.setVisibility(8);
            if (com.onetrust.otpublishers.headless.Internal.a.j(str)) {
                this.t.setVisibility(8);
            }
        } else if (this.s.p()) {
            OTLogger.c("TVPCDetail", 3, "Showing Consent Toggle UI");
            this.y.setVisibility(8);
            this.z.setVisibility(8);
            this.d.setText(this.s.b(!this.l.optBoolean("IsIabPurpose")));
            this.e.setText(this.s.h);
            int purposeLegitInterestLocal = this.k.getPurposeLegitInterestLocal(this.l.optString("CustomGroupId"));
            int i2 = (!this.s.i || purposeLegitInterestLocal <= -1) ? 8 : 0;
            this.u.setVisibility(i2);
            this.x.setVisibility(i2);
            this.w.setVisibility(0);
            if (i2 == 0) {
                this.x.setChecked(purposeLegitInterestLocal == 1);
            }
            this.w.setChecked(this.k.getPurposeConsentLocal(this.l.optString("CustomGroupId")) == 1);
        }
        this.c.setVisibility(8);
        this.r.setVisibility(this.C.getVisibility());
        this.r.setVisibility(this.D.getVisibility());
        if (this.p) {
            return;
        }
        JSONObject jSONObject5 = this.l;
        if (jSONObject5.has("SubGroups") && jSONObject5.optBoolean("ShowSubgroup")) {
            Context context2 = this.g;
            SharedPreferences sharedPreferences = context2.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
            if (Q.a(context2)) {
                fVar = new com.onetrust.otpublishers.headless.Internal.Preferences.f(context2, sharedPreferences, sharedPreferences.getString("OT_ACTIVE_PROFILE_ID", ""));
            } else {
                fVar = null;
                z = false;
            }
            if (z) {
                sharedPreferences = fVar;
            }
            String string = sharedPreferences.getString("OT_VENDOR_COUNT_FOR_CATEGORIES", "");
            OTLogger.c("IAB2V2Flow", 3, "Getting vendorCountForCategoryString = " + string);
            if (com.onetrust.otpublishers.headless.Internal.a.j(string)) {
                jSONObject = new JSONObject();
            } else {
                try {
                    jSONObject = new JSONObject(string);
                } catch (JSONException e) {
                    Z.p("Error on getting vendor count for categories : ", e, "OTSPUtils", 6);
                }
            }
            JSONObject jSONObject6 = jSONObject;
            JSONArray jSONArrayOptJSONArray = this.l.optJSONArray("SubGroups");
            Objects.requireNonNull(jSONArrayOptJSONArray);
            com.onetrust.otpublishers.headless.UI.TVUI.adapter.l lVar = new com.onetrust.otpublishers.headless.UI.TVUI.adapter.l(jSONArrayOptJSONArray, this.g, this.k, this, jSONObject6);
            this.q = lVar;
            this.f.setAdapter(lVar);
            this.c.setText(bVarA.d);
            this.c.setVisibility(0);
            this.r.setVisibility(this.u.getVisibility());
        }
    }

    public final void K(String str, String str2) {
        int[][] iArr = {new int[]{R.attr.state_checked}, new int[0]};
        int[] iArr2 = {Color.parseColor(str), Color.parseColor(str)};
        this.x.setButtonTintList(new ColorStateList(iArr, iArr2));
        this.z.setButtonTintList(new ColorStateList(iArr, iArr2));
        this.e.setTextColor(Color.parseColor(str));
        this.i.setBackgroundColor(Color.parseColor(str2));
        AbstractC3617f4.f(this.e, str);
    }

    @Override // com.onetrust.otpublishers.headless.UI.TVUI.adapter.j
    public final void a() {
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
        View viewInflate = layoutInflater.inflate(com.quizlet.quizletandroid.R.layout.ot_pc_subgroupdetail_tv, viewGroup, false);
        this.a = (TextView) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.tv_category_title);
        this.b = (TextView) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.tv_category_desc);
        this.h = (LinearLayout) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.group_status_on);
        this.i = (LinearLayout) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.group_status_off);
        this.f = (RecyclerView) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.tv_subgroup_list);
        this.c = (TextView) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.subgroup_list_title);
        this.r = viewInflate.findViewById(com.quizlet.quizletandroid.R.id.ot_grp_dtl_sg_div);
        this.m = (LinearLayout) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.tv_grp_detail_lyt);
        this.t = (CardView) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.tv_sg_card_on);
        this.u = (CardView) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.tv_sg_card_off);
        this.y = (CheckBox) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.tv_consent_on_sg_cb);
        this.z = (CheckBox) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.tv_consent_off_sg_cb);
        this.d = (TextView) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.group_status_on_tv);
        this.e = (TextView) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.group_status_off_tv);
        this.j = (TextView) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.ot_iab_legal_desc_tv);
        this.v = (TextView) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.always_active_status_iab);
        this.w = (CheckBox) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.tv_consent_cb);
        this.x = (CheckBox) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.tv_li_cb);
        this.A = (ImageView) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.tv_sub_grp_back);
        this.f.setHasFixedSize(true);
        this.f.setLayoutManager(new LinearLayoutManager(getActivity()));
        this.t.setOnKeyListener(this);
        this.u.setOnKeyListener(this);
        this.t.setOnFocusChangeListener(this);
        this.u.setOnFocusChangeListener(this);
        this.A.setOnKeyListener(this);
        this.j.setOnKeyListener(this);
        this.A.setOnFocusChangeListener(this);
        this.I = (CardView) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.card_list_of_sdks_sg);
        this.J = (LinearLayout) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.list_of_sdks_lyt_sg);
        this.K = (TextView) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.list_of_sdks_sg_tv);
        final int i = 0;
        this.w.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener(this) { // from class: com.onetrust.otpublishers.headless.UI.TVUI.fragments.h
            public final /* synthetic */ i b;

            {
                this.b = this;
            }

            @Override // android.widget.CompoundButton.OnCheckedChangeListener
            public final void onCheckedChanged(CompoundButton compoundButton, boolean z) throws JSONException {
                switch (i) {
                    case 0:
                        i iVar = this.b;
                        iVar.B = iVar.B > 1 ? 3 : 1;
                        break;
                    default:
                        i iVar2 = this.b;
                        String strOptString = iVar2.l.optString("CustomGroupId");
                        iVar2.k.updatePurposeLegitInterest(strOptString, z);
                        androidx.compose.foundation.lazy.grid.m mVar = new androidx.compose.foundation.lazy.grid.m(11, 4);
                        mVar.c = strOptString;
                        mVar.b = z ? 1 : 0;
                        com.onetrust.otpublishers.headless.Internal.Event.a aVar = iVar2.n;
                        if (aVar != null) {
                            aVar.a(mVar);
                        } else {
                            OTLogger.c("OneTrust", 6, "Error on sending UI events, listener set was found to be null.This could be because the activity has been recreated. \n Please set listener to get UI event callbacks.");
                        }
                        int i2 = 0;
                        if (iVar2.l.has("SubGroups") && com.onetrust.otpublishers.headless.Internal.a.j(iVar2.l.optString("Parent"))) {
                            OTPublishersHeadlessSDK oTPublishersHeadlessSDK = iVar2.k;
                            JSONObject jSONObject = iVar2.l;
                            while (i2 < jSONObject.getJSONArray("SubGroups").length()) {
                                try {
                                    oTPublishersHeadlessSDK.updatePurposeLegitInterest(jSONObject.getJSONArray("SubGroups").getJSONObject(i2).optString("CustomGroupId"), z);
                                    i2++;
                                } catch (Exception e) {
                                    Z.n("error while updating subgroup LI status on TV, err : ", e, "OneTrust", 6);
                                }
                            }
                        } else if (!iVar2.l.has("SubGroups") && !com.onetrust.otpublishers.headless.Internal.a.j(iVar2.l.optString("Parent"))) {
                            String strOptString2 = iVar2.l.optString("Parent");
                            if (z) {
                                try {
                                    com.onetrust.otpublishers.headless.UI.TVUI.datautils.c cVarI = com.onetrust.otpublishers.headless.UI.TVUI.datautils.c.i();
                                    OTPublishersHeadlessSDK oTPublishersHeadlessSDK2 = iVar2.k;
                                    JSONObject jSONObject2 = cVarI.c;
                                    if (jSONObject2.names().toString().contains(strOptString2)) {
                                        JSONArray jSONArrayOptJSONArray = jSONObject2.optJSONArray(strOptString2);
                                        while (true) {
                                            if (i2 >= jSONArrayOptJSONArray.length()) {
                                                iVar2.k.updatePurposeLegitInterest(strOptString2, true);
                                            } else if (oTPublishersHeadlessSDK2.getPurposeLegitInterestLocal(jSONArrayOptJSONArray.getString(i2)) != 0) {
                                                i2++;
                                            }
                                        }
                                    }
                                } catch (JSONException e2) {
                                    Z.p("error while updating parent LI status on TV, err: ", e2, "OneTrust", 6);
                                }
                            } else {
                                iVar2.k.updatePurposeLegitInterest(strOptString2, false);
                            }
                        }
                        com.onetrust.otpublishers.headless.UI.TVUI.adapter.l lVar = iVar2.q;
                        if (lVar != null) {
                            lVar.notifyDataSetChanged();
                        }
                        int i3 = iVar2.B;
                        int i4 = 2;
                        if (i3 != 0 && i3 != 2) {
                            i4 = 3;
                        }
                        iVar2.B = i4;
                        break;
                }
            }
        });
        final int i2 = 1;
        this.x.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener(this) { // from class: com.onetrust.otpublishers.headless.UI.TVUI.fragments.h
            public final /* synthetic */ i b;

            {
                this.b = this;
            }

            @Override // android.widget.CompoundButton.OnCheckedChangeListener
            public final void onCheckedChanged(CompoundButton compoundButton, boolean z) throws JSONException {
                switch (i2) {
                    case 0:
                        i iVar = this.b;
                        iVar.B = iVar.B > 1 ? 3 : 1;
                        break;
                    default:
                        i iVar2 = this.b;
                        String strOptString = iVar2.l.optString("CustomGroupId");
                        iVar2.k.updatePurposeLegitInterest(strOptString, z);
                        androidx.compose.foundation.lazy.grid.m mVar = new androidx.compose.foundation.lazy.grid.m(11, 4);
                        mVar.c = strOptString;
                        mVar.b = z ? 1 : 0;
                        com.onetrust.otpublishers.headless.Internal.Event.a aVar = iVar2.n;
                        if (aVar != null) {
                            aVar.a(mVar);
                        } else {
                            OTLogger.c("OneTrust", 6, "Error on sending UI events, listener set was found to be null.This could be because the activity has been recreated. \n Please set listener to get UI event callbacks.");
                        }
                        int i22 = 0;
                        if (iVar2.l.has("SubGroups") && com.onetrust.otpublishers.headless.Internal.a.j(iVar2.l.optString("Parent"))) {
                            OTPublishersHeadlessSDK oTPublishersHeadlessSDK = iVar2.k;
                            JSONObject jSONObject = iVar2.l;
                            while (i22 < jSONObject.getJSONArray("SubGroups").length()) {
                                try {
                                    oTPublishersHeadlessSDK.updatePurposeLegitInterest(jSONObject.getJSONArray("SubGroups").getJSONObject(i22).optString("CustomGroupId"), z);
                                    i22++;
                                } catch (Exception e) {
                                    Z.n("error while updating subgroup LI status on TV, err : ", e, "OneTrust", 6);
                                }
                            }
                        } else if (!iVar2.l.has("SubGroups") && !com.onetrust.otpublishers.headless.Internal.a.j(iVar2.l.optString("Parent"))) {
                            String strOptString2 = iVar2.l.optString("Parent");
                            if (z) {
                                try {
                                    com.onetrust.otpublishers.headless.UI.TVUI.datautils.c cVarI = com.onetrust.otpublishers.headless.UI.TVUI.datautils.c.i();
                                    OTPublishersHeadlessSDK oTPublishersHeadlessSDK2 = iVar2.k;
                                    JSONObject jSONObject2 = cVarI.c;
                                    if (jSONObject2.names().toString().contains(strOptString2)) {
                                        JSONArray jSONArrayOptJSONArray = jSONObject2.optJSONArray(strOptString2);
                                        while (true) {
                                            if (i22 >= jSONArrayOptJSONArray.length()) {
                                                iVar2.k.updatePurposeLegitInterest(strOptString2, true);
                                            } else if (oTPublishersHeadlessSDK2.getPurposeLegitInterestLocal(jSONArrayOptJSONArray.getString(i22)) != 0) {
                                                i22++;
                                            }
                                        }
                                    }
                                } catch (JSONException e2) {
                                    Z.p("error while updating parent LI status on TV, err: ", e2, "OneTrust", 6);
                                }
                            } else {
                                iVar2.k.updatePurposeLegitInterest(strOptString2, false);
                            }
                        }
                        com.onetrust.otpublishers.headless.UI.TVUI.adapter.l lVar = iVar2.q;
                        if (lVar != null) {
                            lVar.notifyDataSetChanged();
                        }
                        int i3 = iVar2.B;
                        int i4 = 2;
                        if (i3 != 0 && i3 != 2) {
                            i4 = 3;
                        }
                        iVar2.B = i4;
                        break;
                }
            }
        });
        this.C = (CardView) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.card_list_of_partners);
        this.E = (LinearLayout) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.list_of_partners_lyt);
        this.G = (TextView) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.list_of_partners_tv);
        this.D = (CardView) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.card_list_of_policy_link);
        this.F = (LinearLayout) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.list_of_policy_link_layout);
        this.H = (TextView) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.list_of_policy_link_tv);
        this.C.setOnKeyListener(this);
        this.C.setOnFocusChangeListener(this);
        this.D.setOnKeyListener(this);
        this.D.setOnFocusChangeListener(this);
        this.I.setOnKeyListener(this);
        this.I.setOnFocusChangeListener(this);
        J();
        return viewInflate;
    }

    @Override // android.view.View.OnFocusChangeListener
    public final void onFocusChange(View view, boolean z) {
        i iVar;
        boolean z2;
        if (view.getId() == com.quizlet.quizletandroid.R.id.tv_sg_card_on) {
            if (z) {
                androidx.constraintlayout.motion.widget.n nVar = this.s.j.y;
                G((String) nVar.m, (String) nVar.l);
                this.t.setCardElevation(6.0f);
            } else {
                G(this.s.l(), this.L);
                this.t.setCardElevation(1.0f);
            }
        }
        if (view.getId() == com.quizlet.quizletandroid.R.id.tv_sg_card_off) {
            if (z) {
                androidx.constraintlayout.motion.widget.n nVar2 = this.s.j.y;
                K((String) nVar2.m, (String) nVar2.l);
                this.u.setCardElevation(6.0f);
            } else {
                K(this.s.l(), this.L);
                this.u.setCardElevation(1.0f);
            }
        }
        if (view.getId() == com.quizlet.quizletandroid.R.id.card_list_of_partners) {
            I(z, this.s.j.y, this.C, this.E, this.G);
            iVar = this;
            z2 = z;
        } else {
            iVar = this;
            z2 = z;
        }
        if (view.getId() == com.quizlet.quizletandroid.R.id.card_list_of_policy_link) {
            iVar.I(z2, iVar.s.j.y, iVar.D, iVar.F, iVar.H);
        }
        if (view.getId() == com.quizlet.quizletandroid.R.id.card_list_of_sdks_sg) {
            iVar.I(z2, iVar.s.j.y, iVar.I, iVar.J, iVar.K);
        }
        if (view.getId() == com.quizlet.quizletandroid.R.id.tv_sub_grp_back) {
            AbstractC3617f4.i(z2, iVar.s.j.y, iVar.A);
        }
    }

    @Override // android.view.View.OnKeyListener
    public final boolean onKey(View view, int i, KeyEvent keyEvent) throws JSONException {
        Button button;
        if (this.s.p()) {
            if (view.getId() == com.quizlet.quizletandroid.R.id.tv_sg_card_on && AbstractC3617f4.a(i, keyEvent) == 21) {
                boolean z = !this.w.isChecked();
                this.w.setChecked(z);
                H(z);
            } else if (view.getId() == com.quizlet.quizletandroid.R.id.tv_sg_card_off && AbstractC3617f4.a(i, keyEvent) == 21) {
                this.x.setChecked(!r0.isChecked());
            }
        } else if (view.getId() == com.quizlet.quizletandroid.R.id.tv_sg_card_on && AbstractC3617f4.a(i, keyEvent) == 21) {
            if (!this.y.isChecked()) {
                H(true);
                this.y.setChecked(true);
                this.z.setChecked(false);
                this.B = 1;
            }
        } else if (view.getId() == com.quizlet.quizletandroid.R.id.tv_sg_card_off && AbstractC3617f4.a(i, keyEvent) == 21 && !this.z.isChecked()) {
            H(false);
            this.y.setChecked(false);
            this.z.setChecked(true);
            this.B = 1;
        }
        if (view.getId() == com.quizlet.quizletandroid.R.id.card_list_of_partners && AbstractC3617f4.a(i, keyEvent) == 21) {
            HashMap map = new HashMap();
            map.put(this.l.optString("CustomGroupId"), this.l.optString("Type"));
            g gVar = this.o.c;
            gVar.y = 4;
            a aVar = gVar.z;
            if (aVar != null && aVar.getArguments() != null) {
                gVar.z.getArguments().putInt("OT_TV_FOCUSED_BTN", 1);
            }
            gVar.Q(map, true, false);
        }
        if (view.getId() == com.quizlet.quizletandroid.R.id.card_list_of_policy_link && AbstractC3617f4.a(i, keyEvent) == 21) {
            this.o.I(this.l, true, true);
        }
        if (view.getId() == com.quizlet.quizletandroid.R.id.tv_sub_grp_back && AbstractC3617f4.a(i, keyEvent) == 21) {
            boolean z2 = this.k.getPurposeConsentLocal(this.l.optString("CustomGroupId")) == 1;
            boolean z3 = this.k.getPurposeLegitInterestLocal(this.l.optString("CustomGroupId")) == 1;
            k kVar = this.o;
            int i2 = this.B;
            kVar.getChildFragmentManager().W();
            d dVar = kVar.o;
            if (dVar != null) {
                dVar.W.requestFocus();
                if (i2 == 1) {
                    kVar.o.I(z2);
                } else if (i2 == 2) {
                    kVar.o.M(z3);
                } else if (i2 == 3) {
                    kVar.o.I(z2);
                    kVar.o.M(z3);
                }
            }
        }
        if (view.getId() != com.quizlet.quizletandroid.R.id.ot_iab_legal_desc_tv || keyEvent.getKeyCode() != 20) {
            if (view.getId() == com.quizlet.quizletandroid.R.id.card_list_of_sdks_sg && AbstractC3617f4.a(i, keyEvent) == 21) {
                ArrayList arrayList = new ArrayList();
                arrayList.add(this.l.optString("CustomGroupId"));
                this.o.H(arrayList);
            }
            return false;
        }
        k kVar2 = this.o;
        if (kVar2.f.getVisibility() == 0) {
            button = kVar2.f;
        } else if (kVar2.g.getVisibility() == 0) {
            button = kVar2.g;
        } else {
            if (kVar2.e.getVisibility() != 0) {
                return true;
            }
            button = kVar2.e;
        }
        button.requestFocus();
        return true;
    }

    @Override // com.onetrust.otpublishers.headless.UI.TVUI.adapter.j
    public final void a(JSONObject jSONObject) {
        this.o.I(jSONObject, true, false);
    }
}

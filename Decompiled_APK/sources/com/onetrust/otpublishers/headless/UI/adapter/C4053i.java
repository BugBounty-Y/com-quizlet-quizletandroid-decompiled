package com.onetrust.otpublishers.headless.UI.adapter;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.res.Resources;
import android.graphics.Color;
import android.graphics.Typeface;
import android.view.View;
import android.view.ViewGroup;
import android.widget.CompoundButton;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.appcompat.widget.SwitchCompat;
import androidx.core.view.V;
import androidx.recyclerview.widget.AbstractC1361d0;
import androidx.recyclerview.widget.F0;
import com.google.android.gms.internal.ads.Zh;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3605e0;
import com.google.android.gms.internal.mlkit_vision_document_scanner.Q;
import com.google.android.gms.internal.mlkit_vision_document_scanner.Y;
import com.google.android.gms.measurement.internal.Z;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.onetrust.otpublishers.headless.Public.DataModel.OTConfiguration;
import com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK;
import com.quizlet.quizletandroid.R;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* renamed from: com.onetrust.otpublishers.headless.UI.adapter.i, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4053i extends AbstractC1361d0 {
    public final OTConfiguration a;
    public final JSONObject b;
    public final JSONArray c;
    public String d;
    public final Boolean e;
    public final Boolean f;
    public final Boolean g;
    public final OTPublishersHeadlessSDK h;
    public final Context i;
    public final com.onetrust.otpublishers.headless.UI.fragment.k j;
    public final boolean k;
    public boolean l;
    public boolean m;
    public boolean n;
    public final com.onetrust.otpublishers.headless.Internal.Event.a o = new com.onetrust.otpublishers.headless.Internal.Event.a();
    public String p;
    public final String q;
    public final Zh r;
    public JSONObject s;
    public final com.onetrust.otpublishers.headless.UI.mobiledatautils.c t;
    public final String u;
    public final String v;
    public final String w;
    public final boolean x;

    public C4053i(com.onetrust.otpublishers.headless.UI.fragment.k kVar, Context context, boolean z, OTConfiguration oTConfiguration, com.onetrust.otpublishers.headless.UI.mobiledatautils.c cVar, OTPublishersHeadlessSDK oTPublishersHeadlessSDK, JSONObject jSONObject) {
        this.t = cVar;
        this.c = cVar.a.optJSONArray("SubGroups");
        this.e = Boolean.valueOf(z);
        this.f = Boolean.valueOf(cVar.f);
        this.g = Boolean.valueOf(cVar.e);
        this.k = cVar.g;
        this.h = oTPublishersHeadlessSDK;
        this.i = context;
        this.j = kVar;
        this.q = cVar.k;
        Zh zh = cVar.l;
        this.r = zh;
        this.a = oTConfiguration;
        this.u = (String) zh.f;
        this.v = (String) zh.d;
        this.w = (String) zh.e;
        this.b = jSONObject;
        androidx.room.s sVar = cVar.m;
        this.x = sVar == null || sVar.c;
    }

    public final void d(TextView textView, androidx.navigation.internal.m mVar) throws NumberFormatException {
        OTConfiguration oTConfiguration;
        Typeface otTypeFaceMap;
        textView.setText((String) mVar.g);
        textView.setTextColor(Color.parseColor((String) mVar.b));
        com.google.android.gms.cloudmessaging.k kVar = (com.google.android.gms.cloudmessaging.k) mVar.d;
        String str = (String) kVar.e;
        if (com.onetrust.otpublishers.headless.Internal.a.j(str) || (oTConfiguration = this.a) == null || (otTypeFaceMap = oTConfiguration.getOtTypeFaceMap(str)) == null) {
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

    public final void f(C4052h c4052h) {
        Zh zh = this.r;
        if (zh != null) {
            try {
                d(c4052h.d, (androidx.navigation.internal.m) zh.i);
                d(c4052h.f, (androidx.navigation.internal.m) zh.j);
                k(c4052h.e, (androidx.navigation.internal.m) zh.j);
                d(c4052h.b, (androidx.navigation.internal.m) zh.k);
                d(c4052h.c, (androidx.navigation.internal.m) zh.l);
                d(c4052h.g, (androidx.navigation.internal.m) zh.m);
                d(c4052h.h, (androidx.navigation.internal.m) zh.m);
                String str = (String) zh.c;
                com.google.mlkit.common.internal.model.a.i(c4052h.l, str);
                if (c4052h.getAdapterPosition() == 0) {
                    OTLogger.c("OT_Automation", 3, "setLineBreakColor PC Detail Subgroups List: " + str);
                }
                String str2 = (String) ((androidx.navigation.internal.m) zh.k).g;
                c4052h.i.setContentDescription(str2);
                c4052h.k.setContentDescription(str2);
                c4052h.j.setContentDescription((String) ((androidx.navigation.internal.m) zh.l).g);
            } catch (IllegalArgumentException e) {
                OTLogger.c("OneTrust", 6, "Error while applying Styles to PC Details view, err : " + e.getMessage());
            }
        }
    }

    public final void g(C4052h c4052h, JSONObject jSONObject) throws Resources.NotFoundException {
        if (c4052h.j.getVisibility() == 0) {
            String strOptString = jSONObject.optString("CustomGroupId", "");
            OTPublishersHeadlessSDK oTPublishersHeadlessSDK = this.h;
            boolean z = oTPublishersHeadlessSDK.getPurposeLegitInterestLocal(strOptString) == 1;
            SwitchCompat switchCompat = c4052h.j;
            switchCompat.setChecked(z);
            int purposeLegitInterestLocal = oTPublishersHeadlessSDK.getPurposeLegitInterestLocal(jSONObject.optString("CustomGroupId", ""));
            String str = this.u;
            Context context = this.i;
            if (purposeLegitInterestLocal == 1) {
                assistantMode.utils.studiableMetadata.b.s(context, switchCompat, str, this.v);
            } else {
                assistantMode.utils.studiableMetadata.b.s(context, switchCompat, str, this.w);
            }
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final int getItemCount() {
        JSONArray jSONArray = this.c;
        if (jSONArray != null) {
            return jSONArray.length();
        }
        return 0;
    }

    public final void h(C4052h c4052h, JSONObject jSONObject, String str) {
        if (this.s != null) {
            if (com.onetrust.otpublishers.headless.Internal.a.j(str)) {
                c4052h.f.setVisibility(8);
            } else {
                c4052h.f.setVisibility(0);
            }
            String str2 = this.q;
            boolean zEqualsIgnoreCase = str2.equalsIgnoreCase("user_friendly");
            Context context = this.i;
            if (!zEqualsIgnoreCase) {
                if (str2.equalsIgnoreCase("legal")) {
                    if (!jSONObject.getString("Type").equals("COOKIE")) {
                        assistantMode.utils.studiableMetadata.b.r(context, c4052h.f, this.p);
                        return;
                    }
                } else if (!this.s.isNull(str2) && !com.onetrust.otpublishers.headless.Internal.a.j(str2)) {
                    return;
                }
            }
            assistantMode.utils.studiableMetadata.b.r(context, c4052h.f, str);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:55:0x012b  */
    /* JADX WARN: Removed duplicated region for block: B:61:0x0146  */
    /* JADX WARN: Removed duplicated region for block: B:66:0x015e  */
    /* JADX WARN: Removed duplicated region for block: B:70:0x0189 A[Catch: JSONException -> 0x0191, TRY_ENTER, TryCatch #0 {JSONException -> 0x0191, blocks: (B:67:0x0175, B:70:0x0189, B:74:0x0193), top: B:80:0x0175 }] */
    /* JADX WARN: Removed duplicated region for block: B:74:0x0193 A[Catch: JSONException -> 0x0191, TRY_LEAVE, TryCatch #0 {JSONException -> 0x0191, blocks: (B:67:0x0175, B:70:0x0189, B:74:0x0193), top: B:80:0x0175 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void i(com.onetrust.otpublishers.headless.UI.adapter.C4052h r18, org.json.JSONObject r19, boolean r20) {
        /*
            Method dump skipped, instructions count: 466
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.UI.adapter.C4053i.i(com.onetrust.otpublishers.headless.UI.adapter.h, org.json.JSONObject, boolean):void");
    }

    public final void j(String str, String str2, boolean z, boolean z2) {
        int purposeLegitInterestLocal;
        com.onetrust.otpublishers.headless.Internal.Preferences.f fVar;
        com.onetrust.otpublishers.headless.UI.fragment.k kVar = this.j;
        OTPublishersHeadlessSDK oTPublishersHeadlessSDK = this.h;
        boolean z3 = true;
        if (z) {
            JSONArray jSONArray = this.c;
            int length = jSONArray.length();
            int i = 0;
            for (int i2 = 0; i2 < jSONArray.length(); i2++) {
                JSONObject jSONObject = jSONArray.getJSONObject(i2);
                if (!z2) {
                    purposeLegitInterestLocal = oTPublishersHeadlessSDK.getPurposeConsentLocal(jSONObject.optString("CustomGroupId", ""));
                } else if (oTPublishersHeadlessSDK.getPurposeLegitInterestLocal(jSONObject.optString("CustomGroupId", "")) >= 0) {
                    purposeLegitInterestLocal = oTPublishersHeadlessSDK.getPurposeLegitInterestLocal(jSONArray.getJSONObject(i2).optString("CustomGroupId", ""));
                } else {
                    length--;
                }
                i += purposeLegitInterestLocal;
            }
            if (z2) {
                if (i == length) {
                    kVar.U(str, true, true);
                }
            } else if (jSONArray.length() == i) {
                kVar.U(str, true, false);
            }
        } else {
            kVar.U(str, false, z2);
        }
        new JSONObject();
        Context context = this.i;
        SharedPreferences sharedPreferences = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
        if (Z.r(Boolean.FALSE, Y.a(context), "OT_ENABLE_MULTI_PROFILE")) {
            fVar = new com.onetrust.otpublishers.headless.Internal.Preferences.f(context, sharedPreferences, sharedPreferences.getString("OT_ACTIVE_PROFILE_ID", ""));
        } else {
            fVar = null;
            z3 = false;
        }
        if (z3) {
            sharedPreferences = fVar;
        }
        SharedPreferences sharedPreferences2 = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
        if (Q.a(context)) {
            SharedPreferences sharedPreferences3 = context.getSharedPreferences("com.onetrust.otpublishers.headless.preference.OTT_USER_" + new com.onetrust.otpublishers.headless.Internal.profile.c(context).n(sharedPreferences2.getString("OT_ACTIVE_PROFILE_ID", "")), 0);
            sharedPreferences2.edit();
            sharedPreferences3.edit();
        }
        String string = sharedPreferences.getString("OTT_INTERNAL_SDK_GROUP_MAP", "");
        JSONArray jSONArray2 = new JSONArray();
        if (!com.onetrust.otpublishers.headless.Internal.a.j(string)) {
            try {
                JSONObject jSONObject2 = new JSONObject(string);
                if (jSONObject2.has(str2)) {
                    jSONArray2 = new JSONArray(jSONObject2.get(str2).toString());
                }
            } catch (JSONException e) {
                Z.p("Error while fetching Sdks by group : ", e, "SdkListHelper", 6);
            }
        }
        OTLogger.c("OTPCDetailsAdapter", 4, "SDK Ids of  : " + str2 + " is " + jSONArray2);
        for (int i3 = 0; i3 < jSONArray2.length(); i3++) {
            try {
                oTPublishersHeadlessSDK.updateSDKConsentStatus(jSONArray2.get(i3).toString(), z);
            } catch (JSONException e2) {
                Z.p("Error in setting group sdk status ", e2, "OneTrust", 6);
            }
        }
    }

    public final void k(TextView textView, androidx.navigation.internal.m mVar) {
        OTConfiguration oTConfiguration;
        Typeface otTypeFaceMap;
        textView.setTextColor(Color.parseColor((String) mVar.b));
        com.google.android.gms.cloudmessaging.k kVar = (com.google.android.gms.cloudmessaging.k) mVar.d;
        String str = (String) kVar.e;
        if (com.onetrust.otpublishers.headless.Internal.a.j(str) || (oTConfiguration = this.a) == null || (otTypeFaceMap = oTConfiguration.getOtTypeFaceMap(str)) == null) {
            int iA = com.google.android.gms.cloudmessaging.k.a(textView, kVar.b);
            textView.setTypeface(!com.onetrust.otpublishers.headless.Internal.a.j((String) kVar.c) ? Typeface.create((String) kVar.c, iA) : Typeface.create(textView.getTypeface(), iA));
        } else {
            textView.setTypeface(otTypeFaceMap);
        }
        if (!com.onetrust.otpublishers.headless.Internal.a.j((String) kVar.d)) {
            textView.setTextSize(Float.parseFloat((String) kVar.d));
        }
        if (com.onetrust.otpublishers.headless.Internal.a.j((String) mVar.f)) {
            return;
        }
        textView.setTextAlignment(Integer.parseInt((String) mVar.f));
    }

    /* JADX WARN: Code restructure failed: missing block: B:14:0x0047, code lost:
    
        if (r11 == 1) goto L15;
     */
    /* JADX WARN: Code restructure failed: missing block: B:15:0x0049, code lost:
    
        assistantMode.utils.studiableMetadata.b.s(r3, r10, r1, r9.v);
     */
    /* JADX WARN: Code restructure failed: missing block: B:16:0x004e, code lost:
    
        return;
     */
    /* JADX WARN: Code restructure failed: missing block: B:17:0x004f, code lost:
    
        assistantMode.utils.studiableMetadata.b.s(r3, r10, r1, r9.w);
     */
    /* JADX WARN: Code restructure failed: missing block: B:18:0x0054, code lost:
    
        return;
     */
    /* JADX WARN: Code restructure failed: missing block: B:8:0x002a, code lost:
    
        if (r11 == 1) goto L15;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void l(com.onetrust.otpublishers.headless.UI.adapter.C4052h r10, org.json.JSONObject r11) throws android.content.res.Resources.NotFoundException {
        /*
            r9 = this;
            boolean r0 = r9.m
            java.lang.String r1 = r9.u
            r2 = 0
            android.content.Context r3 = r9.i
            java.lang.String r4 = ""
            java.lang.String r5 = "CustomGroupId"
            com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK r6 = r9.h
            r7 = 1
            if (r0 == 0) goto L2d
            androidx.appcompat.widget.SwitchCompat r0 = r10.i
            java.lang.String r8 = r11.optString(r5, r4)
            int r8 = r6.getPurposeConsentLocal(r8)
            if (r8 != r7) goto L1d
            r2 = r7
        L1d:
            r0.setChecked(r2)
            java.lang.String r11 = r11.optString(r5, r4)
            int r11 = r6.getPurposeConsentLocal(r11)
            androidx.appcompat.widget.SwitchCompat r10 = r10.i
            if (r11 != r7) goto L4f
            goto L49
        L2d:
            androidx.appcompat.widget.SwitchCompat r0 = r10.k
            java.lang.String r8 = r11.optString(r5, r4)
            int r8 = r6.getPurposeConsentLocal(r8)
            if (r8 != r7) goto L3a
            r2 = r7
        L3a:
            r0.setChecked(r2)
            java.lang.String r11 = r11.optString(r5, r4)
            int r11 = r6.getPurposeConsentLocal(r11)
            androidx.appcompat.widget.SwitchCompat r10 = r10.k
            if (r11 != r7) goto L4f
        L49:
            java.lang.String r11 = r9.v
            assistantMode.utils.studiableMetadata.b.s(r3, r10, r1, r11)
            return
        L4f:
            java.lang.String r11 = r9.w
            assistantMode.utils.studiableMetadata.b.s(r3, r10, r1, r11)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.UI.adapter.C4053i.l(com.onetrust.otpublishers.headless.UI.adapter.h, org.json.JSONObject):void");
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final void onBindViewHolder(F0 f0, final int i) throws JSONException, Resources.NotFoundException, NumberFormatException {
        com.onetrust.otpublishers.headless.Internal.Preferences.f fVar;
        boolean z;
        Zh zh = this.r;
        Context context = this.i;
        final C4052h c4052h = (C4052h) f0;
        c4052h.setIsRecyclable(false);
        SwitchCompat switchCompat = c4052h.j;
        SwitchCompat switchCompat2 = c4052h.k;
        SwitchCompat switchCompat3 = c4052h.i;
        TextView textView = c4052h.g;
        TextView textView2 = c4052h.d;
        LinearLayout linearLayout = c4052h.m;
        TextView textView3 = c4052h.a;
        try {
            this.s = this.h.getPreferenceCenterData();
            SharedPreferences sharedPreferences = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
            String str = "";
            if (AbstractC3605e0.a(context.getSharedPreferences("com.onetrust.otpublishers.headless.preference".concat("OTT_DEFAULT_USER"), 0).getString("OT_ENABLE_MULTI_PROFILE", Boolean.FALSE.toString()))) {
                fVar = new com.onetrust.otpublishers.headless.Internal.Preferences.f(context, sharedPreferences, sharedPreferences.getString("OT_ACTIVE_PROFILE_ID", ""));
                z = true;
            } else {
                fVar = null;
                z = false;
            }
            if (z) {
                sharedPreferences = fVar;
            }
            String string = sharedPreferences.getString("OT_TEMPLATE_TYPE", "");
            if (!com.onetrust.otpublishers.headless.Internal.a.j(string)) {
                str = string;
            }
            this.m = "IAB2".equalsIgnoreCase(str) || "IAB2V2".equalsIgnoreCase(str);
            f(c4052h);
            final JSONObject jSONObject = this.c.getJSONObject(c4052h.getAdapterPosition());
            this.l = jSONObject.optBoolean("HasLegIntOptOut", false);
            this.n = jSONObject.optBoolean("HasConsentOptOut", false);
            this.d = jSONObject.getString("Type");
            boolean zOptBoolean = jSONObject.optBoolean("HasLegIntOptOut", false);
            boolean z2 = this.m;
            TextView textView4 = c4052h.c;
            if (z2 && jSONObject.getString("Type").contains("IAB")) {
                textView4.setVisibility(0);
            } else {
                textView4.setVisibility(8);
            }
            String strOptString = jSONObject.optString("GroupNameMobile");
            if (com.onetrust.otpublishers.headless.Internal.a.j(strOptString)) {
                strOptString = jSONObject.optString("GroupName");
            }
            textView2.setText(strOptString);
            V.p(textView2, true);
            if (com.google.mlkit.common.internal.model.a.m(context)) {
                com.google.mlkit.common.internal.model.a.h(context, strOptString, linearLayout, R.id.consent_toggle);
                com.google.mlkit.common.internal.model.a.h(context, strOptString, linearLayout, R.id.legitInt_toggle);
                com.google.mlkit.common.internal.model.a.h(context, strOptString, linearLayout, R.id.consent_toggle_non_iab);
            }
            String strOptString2 = jSONObject.optString("GroupDescription");
            if (jSONObject.has("DescriptionLegal")) {
                this.p = jSONObject.getString("DescriptionLegal");
            }
            String str2 = (String) ((androidx.navigation.internal.m) zh.m).g;
            textView.setText(str2);
            c4052h.h.setText(str2);
            h(c4052h, jSONObject, strOptString2);
            l(c4052h, jSONObject);
            final int i2 = 0;
            switchCompat3.setOnClickListener(new View.OnClickListener(this) { // from class: com.onetrust.otpublishers.headless.UI.adapter.g
                public final /* synthetic */ C4053i b;

                {
                    this.b = this;
                }

                @Override // android.view.View.OnClickListener
                public final void onClick(View view) {
                    switch (i2) {
                        case 0:
                            int i3 = i;
                            C4052h c4052h2 = c4052h;
                            C4053i c4053i = this.b;
                            JSONArray jSONArray = c4053i.c;
                            try {
                                c4053i.j(jSONArray.getJSONObject(i3).getString("Parent"), jSONArray.getJSONObject(i3).optString("CustomGroupId", ""), c4052h2.i.isChecked(), false);
                                break;
                            } catch (JSONException e) {
                                Z.p("Error while setting parent status ", e, "OTPCDetailsAdapter", 6);
                                return;
                            }
                        default:
                            int i4 = i;
                            C4052h c4052h3 = c4052h;
                            C4053i c4053i2 = this.b;
                            JSONArray jSONArray2 = c4053i2.c;
                            try {
                                c4053i2.j(jSONArray2.getJSONObject(i4).getString("Parent"), jSONArray2.getJSONObject(i4).optString("CustomGroupId", ""), c4052h3.k.isChecked(), false);
                                break;
                            } catch (JSONException e2) {
                                Z.p("Error while setting parent status ", e2, "OTPCDetailsAdapter", 6);
                            }
                    }
                }
            });
            final int i3 = 1;
            switchCompat2.setOnClickListener(new View.OnClickListener(this) { // from class: com.onetrust.otpublishers.headless.UI.adapter.g
                public final /* synthetic */ C4053i b;

                {
                    this.b = this;
                }

                @Override // android.view.View.OnClickListener
                public final void onClick(View view) {
                    switch (i3) {
                        case 0:
                            int i32 = i;
                            C4052h c4052h2 = c4052h;
                            C4053i c4053i = this.b;
                            JSONArray jSONArray = c4053i.c;
                            try {
                                c4053i.j(jSONArray.getJSONObject(i32).getString("Parent"), jSONArray.getJSONObject(i32).optString("CustomGroupId", ""), c4052h2.i.isChecked(), false);
                                break;
                            } catch (JSONException e) {
                                Z.p("Error while setting parent status ", e, "OTPCDetailsAdapter", 6);
                                return;
                            }
                        default:
                            int i4 = i;
                            C4052h c4052h3 = c4052h;
                            C4053i c4053i2 = this.b;
                            JSONArray jSONArray2 = c4053i2.c;
                            try {
                                c4053i2.j(jSONArray2.getJSONObject(i4).getString("Parent"), jSONArray2.getJSONObject(i4).optString("CustomGroupId", ""), c4052h3.k.isChecked(), false);
                                break;
                            } catch (JSONException e2) {
                                Z.p("Error while setting parent status ", e2, "OTPCDetailsAdapter", 6);
                            }
                    }
                }
            });
            textView3.setOnClickListener(new com.braze.ui.inappmessage.views.a(8, this, jSONObject));
            final int i4 = 1;
            switchCompat3.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() { // from class: com.onetrust.otpublishers.headless.UI.adapter.f
                @Override // android.widget.CompoundButton.OnCheckedChangeListener
                public final void onCheckedChanged(CompoundButton compoundButton, boolean z3) throws JSONException {
                    SwitchCompat switchCompat4;
                    String str3;
                    SwitchCompat switchCompat5;
                    String str4;
                    SwitchCompat switchCompat6;
                    String str5;
                    switch (i4) {
                        case 0:
                            JSONObject jSONObject2 = jSONObject;
                            C4053i c4053i = this;
                            String str6 = c4053i.u;
                            Context context2 = c4053i.i;
                            try {
                                String string2 = jSONObject2.getString("CustomGroupId");
                                c4053i.h.updatePurposeLegitInterest(string2, z3);
                                androidx.compose.foundation.lazy.grid.m mVar = new androidx.compose.foundation.lazy.grid.m(11, 4);
                                mVar.c = string2;
                                mVar.b = z3 ? 1 : 0;
                                com.onetrust.otpublishers.headless.Internal.Event.a aVar = c4053i.o;
                                if (aVar != null) {
                                    aVar.a(mVar);
                                } else {
                                    OTLogger.c("OneTrust", 6, "Error on sending UI events, listener set was found to be null.This could be because the activity has been recreated. \n Please set listener to get UI event callbacks.");
                                }
                                C4052h c4052h2 = c4052h;
                                if (z3) {
                                    switchCompat4 = c4052h2.j;
                                    str3 = c4053i.v;
                                } else {
                                    switchCompat4 = c4052h2.j;
                                    str3 = c4053i.w;
                                }
                                assistantMode.utils.studiableMetadata.b.s(context2, switchCompat4, str6, str3);
                                break;
                            } catch (JSONException e) {
                                Z.p("Error while updating LI status ", e, "OTPCDetailsAdapter", 6);
                                return;
                            }
                        case 1:
                            JSONObject jSONObject3 = jSONObject;
                            C4053i c4053i2 = this;
                            String str7 = c4053i2.u;
                            Context context3 = c4053i2.i;
                            try {
                                String string3 = jSONObject3.getString("CustomGroupId");
                                c4053i2.h.updatePurposeConsent(string3, z3);
                                androidx.compose.foundation.lazy.grid.m mVar2 = new androidx.compose.foundation.lazy.grid.m(7, 4);
                                mVar2.c = string3;
                                mVar2.b = z3 ? 1 : 0;
                                com.onetrust.otpublishers.headless.Internal.Event.a aVar2 = c4053i2.o;
                                if (aVar2 != null) {
                                    aVar2.a(mVar2);
                                } else {
                                    OTLogger.c("OneTrust", 6, "Error on sending UI events, listener set was found to be null.This could be because the activity has been recreated. \n Please set listener to get UI event callbacks.");
                                }
                                C4052h c4052h3 = c4052h;
                                if (z3) {
                                    switchCompat5 = c4052h3.i;
                                    str4 = c4053i2.v;
                                } else {
                                    switchCompat5 = c4052h3.i;
                                    str4 = c4053i2.w;
                                }
                                assistantMode.utils.studiableMetadata.b.s(context3, switchCompat5, str7, str4);
                                break;
                            } catch (JSONException e2) {
                                Z.p("Error while updating consent status ", e2, "OTPCDetailsAdapter", 6);
                                return;
                            }
                        default:
                            JSONObject jSONObject4 = jSONObject;
                            C4053i c4053i3 = this;
                            String str8 = c4053i3.u;
                            Context context4 = c4053i3.i;
                            try {
                                String string4 = jSONObject4.getString("CustomGroupId");
                                c4053i3.h.updatePurposeConsent(string4, z3);
                                androidx.compose.foundation.lazy.grid.m mVar3 = new androidx.compose.foundation.lazy.grid.m(7, 4);
                                mVar3.c = string4;
                                mVar3.b = z3 ? 1 : 0;
                                com.onetrust.otpublishers.headless.Internal.Event.a aVar3 = c4053i3.o;
                                if (aVar3 != null) {
                                    aVar3.a(mVar3);
                                } else {
                                    OTLogger.c("OneTrust", 6, "Error on sending UI events, listener set was found to be null.This could be because the activity has been recreated. \n Please set listener to get UI event callbacks.");
                                }
                                C4052h c4052h4 = c4052h;
                                if (z3) {
                                    switchCompat6 = c4052h4.k;
                                    str5 = c4053i3.v;
                                } else {
                                    switchCompat6 = c4052h4.k;
                                    str5 = c4053i3.w;
                                }
                                assistantMode.utils.studiableMetadata.b.s(context4, switchCompat6, str8, str5);
                                break;
                            } catch (JSONException e3) {
                                Z.p("Error while updating consent status ", e3, "OTPCDetailsAdapter", 6);
                            }
                    }
                }
            });
            final int i5 = 2;
            switchCompat2.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() { // from class: com.onetrust.otpublishers.headless.UI.adapter.f
                @Override // android.widget.CompoundButton.OnCheckedChangeListener
                public final void onCheckedChanged(CompoundButton compoundButton, boolean z3) throws JSONException {
                    SwitchCompat switchCompat4;
                    String str3;
                    SwitchCompat switchCompat5;
                    String str4;
                    SwitchCompat switchCompat6;
                    String str5;
                    switch (i5) {
                        case 0:
                            JSONObject jSONObject2 = jSONObject;
                            C4053i c4053i = this;
                            String str6 = c4053i.u;
                            Context context2 = c4053i.i;
                            try {
                                String string2 = jSONObject2.getString("CustomGroupId");
                                c4053i.h.updatePurposeLegitInterest(string2, z3);
                                androidx.compose.foundation.lazy.grid.m mVar = new androidx.compose.foundation.lazy.grid.m(11, 4);
                                mVar.c = string2;
                                mVar.b = z3 ? 1 : 0;
                                com.onetrust.otpublishers.headless.Internal.Event.a aVar = c4053i.o;
                                if (aVar != null) {
                                    aVar.a(mVar);
                                } else {
                                    OTLogger.c("OneTrust", 6, "Error on sending UI events, listener set was found to be null.This could be because the activity has been recreated. \n Please set listener to get UI event callbacks.");
                                }
                                C4052h c4052h2 = c4052h;
                                if (z3) {
                                    switchCompat4 = c4052h2.j;
                                    str3 = c4053i.v;
                                } else {
                                    switchCompat4 = c4052h2.j;
                                    str3 = c4053i.w;
                                }
                                assistantMode.utils.studiableMetadata.b.s(context2, switchCompat4, str6, str3);
                                break;
                            } catch (JSONException e) {
                                Z.p("Error while updating LI status ", e, "OTPCDetailsAdapter", 6);
                                return;
                            }
                        case 1:
                            JSONObject jSONObject3 = jSONObject;
                            C4053i c4053i2 = this;
                            String str7 = c4053i2.u;
                            Context context3 = c4053i2.i;
                            try {
                                String string3 = jSONObject3.getString("CustomGroupId");
                                c4053i2.h.updatePurposeConsent(string3, z3);
                                androidx.compose.foundation.lazy.grid.m mVar2 = new androidx.compose.foundation.lazy.grid.m(7, 4);
                                mVar2.c = string3;
                                mVar2.b = z3 ? 1 : 0;
                                com.onetrust.otpublishers.headless.Internal.Event.a aVar2 = c4053i2.o;
                                if (aVar2 != null) {
                                    aVar2.a(mVar2);
                                } else {
                                    OTLogger.c("OneTrust", 6, "Error on sending UI events, listener set was found to be null.This could be because the activity has been recreated. \n Please set listener to get UI event callbacks.");
                                }
                                C4052h c4052h3 = c4052h;
                                if (z3) {
                                    switchCompat5 = c4052h3.i;
                                    str4 = c4053i2.v;
                                } else {
                                    switchCompat5 = c4052h3.i;
                                    str4 = c4053i2.w;
                                }
                                assistantMode.utils.studiableMetadata.b.s(context3, switchCompat5, str7, str4);
                                break;
                            } catch (JSONException e2) {
                                Z.p("Error while updating consent status ", e2, "OTPCDetailsAdapter", 6);
                                return;
                            }
                        default:
                            JSONObject jSONObject4 = jSONObject;
                            C4053i c4053i3 = this;
                            String str8 = c4053i3.u;
                            Context context4 = c4053i3.i;
                            try {
                                String string4 = jSONObject4.getString("CustomGroupId");
                                c4053i3.h.updatePurposeConsent(string4, z3);
                                androidx.compose.foundation.lazy.grid.m mVar3 = new androidx.compose.foundation.lazy.grid.m(7, 4);
                                mVar3.c = string4;
                                mVar3.b = z3 ? 1 : 0;
                                com.onetrust.otpublishers.headless.Internal.Event.a aVar3 = c4053i3.o;
                                if (aVar3 != null) {
                                    aVar3.a(mVar3);
                                } else {
                                    OTLogger.c("OneTrust", 6, "Error on sending UI events, listener set was found to be null.This could be because the activity has been recreated. \n Please set listener to get UI event callbacks.");
                                }
                                C4052h c4052h4 = c4052h;
                                if (z3) {
                                    switchCompat6 = c4052h4.k;
                                    str5 = c4053i3.v;
                                } else {
                                    switchCompat6 = c4052h4.k;
                                    str5 = c4053i3.w;
                                }
                                assistantMode.utils.studiableMetadata.b.s(context4, switchCompat6, str8, str5);
                                break;
                            } catch (JSONException e3) {
                                Z.p("Error while updating consent status ", e3, "OTPCDetailsAdapter", 6);
                            }
                    }
                }
            });
            g(c4052h, jSONObject);
            switchCompat.setOnClickListener(new ViewOnClickListenerC4049e(i, c4052h, this, jSONObject));
            final int i6 = 0;
            switchCompat.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() { // from class: com.onetrust.otpublishers.headless.UI.adapter.f
                @Override // android.widget.CompoundButton.OnCheckedChangeListener
                public final void onCheckedChanged(CompoundButton compoundButton, boolean z3) throws JSONException {
                    SwitchCompat switchCompat4;
                    String str3;
                    SwitchCompat switchCompat5;
                    String str4;
                    SwitchCompat switchCompat6;
                    String str5;
                    switch (i6) {
                        case 0:
                            JSONObject jSONObject2 = jSONObject;
                            C4053i c4053i = this;
                            String str6 = c4053i.u;
                            Context context2 = c4053i.i;
                            try {
                                String string2 = jSONObject2.getString("CustomGroupId");
                                c4053i.h.updatePurposeLegitInterest(string2, z3);
                                androidx.compose.foundation.lazy.grid.m mVar = new androidx.compose.foundation.lazy.grid.m(11, 4);
                                mVar.c = string2;
                                mVar.b = z3 ? 1 : 0;
                                com.onetrust.otpublishers.headless.Internal.Event.a aVar = c4053i.o;
                                if (aVar != null) {
                                    aVar.a(mVar);
                                } else {
                                    OTLogger.c("OneTrust", 6, "Error on sending UI events, listener set was found to be null.This could be because the activity has been recreated. \n Please set listener to get UI event callbacks.");
                                }
                                C4052h c4052h2 = c4052h;
                                if (z3) {
                                    switchCompat4 = c4052h2.j;
                                    str3 = c4053i.v;
                                } else {
                                    switchCompat4 = c4052h2.j;
                                    str3 = c4053i.w;
                                }
                                assistantMode.utils.studiableMetadata.b.s(context2, switchCompat4, str6, str3);
                                break;
                            } catch (JSONException e) {
                                Z.p("Error while updating LI status ", e, "OTPCDetailsAdapter", 6);
                                return;
                            }
                        case 1:
                            JSONObject jSONObject3 = jSONObject;
                            C4053i c4053i2 = this;
                            String str7 = c4053i2.u;
                            Context context3 = c4053i2.i;
                            try {
                                String string3 = jSONObject3.getString("CustomGroupId");
                                c4053i2.h.updatePurposeConsent(string3, z3);
                                androidx.compose.foundation.lazy.grid.m mVar2 = new androidx.compose.foundation.lazy.grid.m(7, 4);
                                mVar2.c = string3;
                                mVar2.b = z3 ? 1 : 0;
                                com.onetrust.otpublishers.headless.Internal.Event.a aVar2 = c4053i2.o;
                                if (aVar2 != null) {
                                    aVar2.a(mVar2);
                                } else {
                                    OTLogger.c("OneTrust", 6, "Error on sending UI events, listener set was found to be null.This could be because the activity has been recreated. \n Please set listener to get UI event callbacks.");
                                }
                                C4052h c4052h3 = c4052h;
                                if (z3) {
                                    switchCompat5 = c4052h3.i;
                                    str4 = c4053i2.v;
                                } else {
                                    switchCompat5 = c4052h3.i;
                                    str4 = c4053i2.w;
                                }
                                assistantMode.utils.studiableMetadata.b.s(context3, switchCompat5, str7, str4);
                                break;
                            } catch (JSONException e2) {
                                Z.p("Error while updating consent status ", e2, "OTPCDetailsAdapter", 6);
                                return;
                            }
                        default:
                            JSONObject jSONObject4 = jSONObject;
                            C4053i c4053i3 = this;
                            String str8 = c4053i3.u;
                            Context context4 = c4053i3.i;
                            try {
                                String string4 = jSONObject4.getString("CustomGroupId");
                                c4053i3.h.updatePurposeConsent(string4, z3);
                                androidx.compose.foundation.lazy.grid.m mVar3 = new androidx.compose.foundation.lazy.grid.m(7, 4);
                                mVar3.c = string4;
                                mVar3.b = z3 ? 1 : 0;
                                com.onetrust.otpublishers.headless.Internal.Event.a aVar3 = c4053i3.o;
                                if (aVar3 != null) {
                                    aVar3.a(mVar3);
                                } else {
                                    OTLogger.c("OneTrust", 6, "Error on sending UI events, listener set was found to be null.This could be because the activity has been recreated. \n Please set listener to get UI event callbacks.");
                                }
                                C4052h c4052h4 = c4052h;
                                if (z3) {
                                    switchCompat6 = c4052h4.k;
                                    str5 = c4053i3.v;
                                } else {
                                    switchCompat6 = c4052h4.k;
                                    str5 = c4053i3.w;
                                }
                                assistantMode.utils.studiableMetadata.b.s(context4, switchCompat6, str8, str5);
                                break;
                            } catch (JSONException e3) {
                                Z.p("Error while updating consent status ", e3, "OTPCDetailsAdapter", 6);
                            }
                    }
                }
            });
            boolean z3 = this.k;
            TextView textView5 = c4052h.f;
            if (z3) {
                textView5.setVisibility(0);
            } else {
                textView5.setVisibility(8);
            }
            i(c4052h, jSONObject, zOptBoolean);
            TextView textView6 = c4052h.b;
            if (jSONObject.optString("Status").contains("always") && com.onetrust.otpublishers.headless.Internal.a.j(str2)) {
                textView.setVisibility(8);
                textView6.setVisibility(8);
            }
            if (this.s.optBoolean("IsIabEnabled", false) && jSONObject.optBoolean("IsIabPurpose", false) && com.onetrust.otpublishers.headless.Internal.a.l(this.t.j) && assistantMode.utils.studiableMetadata.b.B(jSONObject)) {
                textView3.setVisibility(0);
            }
            d(textView3, (androidx.navigation.internal.m) ((com.quizlet.data.repository.user.e) zh.p).b);
            if (this.x) {
                textView3.setPaintFlags(textView3.getPaintFlags() | 8);
            }
        } catch (JSONException e) {
            Z.p("error while rendering purpose items in Vendor detail screen ", e, "OneTrust", 6);
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final F0 onCreateViewHolder(ViewGroup viewGroup, int i) {
        return new C4052h(Z.c(viewGroup, R.layout.ot_preference_center_details_item, viewGroup, false));
    }
}

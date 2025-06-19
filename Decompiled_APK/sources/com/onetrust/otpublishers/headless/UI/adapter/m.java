package com.onetrust.otpublishers.headless.UI.adapter;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.res.Resources;
import android.graphics.Color;
import android.graphics.Typeface;
import android.os.Bundle;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import androidx.appcompat.widget.SwitchCompat;
import androidx.recyclerview.widget.AbstractC1361d0;
import androidx.recyclerview.widget.F0;
import com.google.android.gms.internal.mlkit_vision_document_scanner.Q;
import com.google.android.gms.measurement.internal.Z;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.onetrust.otpublishers.headless.Public.DataModel.OTConfiguration;
import com.onetrust.otpublishers.headless.Public.Keys.OTFragmentTags;
import com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK;
import com.quizlet.quizletandroid.R;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class m extends AbstractC1361d0 implements com.onetrust.otpublishers.headless.UI.a {
    public final com.onetrust.otpublishers.headless.UI.fragment.l a;
    public final OTConfiguration b;
    public final OTPublishersHeadlessSDK c;
    public JSONArray d;
    public final Context e;
    public final com.onetrust.otpublishers.headless.Internal.Event.a f;
    public com.onetrust.otpublishers.headless.UI.fragment.k g;
    public com.onetrust.otpublishers.headless.UI.UIProperty.e h;
    public String i;
    public String j;
    public String k;
    public final com.onetrust.otpublishers.headless.UI.mobiledatautils.b l;
    public final assistantMode.utils.studiableMetadata.b m = new assistantMode.utils.studiableMetadata.b(22);
    public final JSONObject n;

    public m(Context context, com.onetrust.otpublishers.headless.UI.mobiledatautils.b bVar, OTPublishersHeadlessSDK oTPublishersHeadlessSDK, com.onetrust.otpublishers.headless.Internal.Event.a aVar, com.onetrust.otpublishers.headless.UI.fragment.l lVar, OTConfiguration oTConfiguration) {
        this.l = bVar;
        this.d = bVar.p;
        this.e = context;
        this.c = oTPublishersHeadlessSDK;
        this.f = aVar;
        this.a = lVar;
        this.h = bVar.u;
        this.b = oTConfiguration;
        this.n = new com.onetrust.otpublishers.headless.Internal.Preferences.e(context).h();
    }

    public final void d(TextView textView, String str, com.onetrust.otpublishers.headless.UI.Helper.c cVar) throws NumberFormatException {
        OTConfiguration oTConfiguration;
        Typeface otTypeFaceMap;
        textView.setText(str);
        textView.setTextColor(Color.parseColor(cVar.b()));
        if (!com.onetrust.otpublishers.headless.Internal.a.j(cVar.r)) {
            textView.setTextSize(Float.parseFloat(cVar.r));
        }
        assistantMode.utils.studiableMetadata.b.x(textView, cVar.q);
        textView.setVisibility(cVar.p);
        com.google.android.gms.cloudmessaging.k kVar = (com.google.android.gms.cloudmessaging.k) cVar.d;
        String str2 = (String) kVar.e;
        if (!com.onetrust.otpublishers.headless.Internal.a.j(str2) && (oTConfiguration = this.b) != null && (otTypeFaceMap = oTConfiguration.getOtTypeFaceMap(str2)) != null) {
            textView.setTypeface(otTypeFaceMap);
        } else {
            int iA = com.google.android.gms.cloudmessaging.k.a(textView, kVar.b);
            textView.setTypeface(!com.onetrust.otpublishers.headless.Internal.a.j((String) kVar.c) ? Typeface.create((String) kVar.c, iA) : Typeface.create(textView.getTypeface(), iA));
        }
    }

    public final void f(C4056l c4056l, int i, boolean z) {
        if (this.d.getJSONObject(i).getString("Status").contains("always")) {
            c4056l.d.setVisibility(8);
            c4056l.c.setVisibility(0);
            return;
        }
        c4056l.c.setVisibility(4);
        SwitchCompat switchCompat = c4056l.d;
        if (z) {
            switchCompat.setVisibility(0);
        } else {
            switchCompat.setVisibility(8);
        }
    }

    public final void g(String str, boolean z) {
        com.onetrust.otpublishers.headless.Internal.Preferences.f fVar;
        boolean z2;
        new JSONObject();
        Context context = this.e;
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
            this.c.updateSDKConsentStatus(jSONArray.get(i).toString(), z);
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final int getItemCount() {
        return this.d.length();
    }

    public final void h(TextView textView, String str, com.onetrust.otpublishers.headless.UI.Helper.c cVar) throws NumberFormatException {
        OTConfiguration oTConfiguration;
        Typeface otTypeFaceMap;
        textView.setText(str);
        textView.setTextColor(Color.parseColor(cVar.b()));
        if (!com.onetrust.otpublishers.headless.Internal.a.j(cVar.r)) {
            textView.setTextSize(Float.parseFloat(cVar.r));
        }
        assistantMode.utils.studiableMetadata.b.x(textView, cVar.q);
        com.google.android.gms.cloudmessaging.k kVar = (com.google.android.gms.cloudmessaging.k) cVar.d;
        String str2 = (String) kVar.e;
        if (!com.onetrust.otpublishers.headless.Internal.a.j(str2) && (oTConfiguration = this.b) != null && (otTypeFaceMap = oTConfiguration.getOtTypeFaceMap(str2)) != null) {
            textView.setTypeface(otTypeFaceMap);
        } else {
            int iA = com.google.android.gms.cloudmessaging.k.a(textView, kVar.b);
            textView.setTypeface(!com.onetrust.otpublishers.headless.Internal.a.j((String) kVar.c) ? Typeface.create((String) kVar.c, iA) : Typeface.create(textView.getTypeface(), iA));
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final void onBindViewHolder(F0 f0, int i) throws JSONException, Resources.NotFoundException, NumberFormatException {
        int i2;
        C4056l c4056l = (C4056l) f0;
        assistantMode.utils.studiableMetadata.b bVar = this.m;
        OTPublishersHeadlessSDK oTPublishersHeadlessSDK = this.c;
        Context context = this.e;
        com.onetrust.otpublishers.headless.UI.mobiledatautils.b bVar2 = this.l;
        try {
            int adapterPosition = c4056l.getAdapterPosition();
            View view = c4056l.f;
            TextView textView = c4056l.a;
            SwitchCompat switchCompat = c4056l.d;
            JSONObject jSONObject = this.d.getJSONObject(adapterPosition);
            com.onetrust.otpublishers.headless.UI.UIProperty.e eVar = this.h;
            this.i = eVar.e;
            this.j = eVar.c;
            this.k = eVar.d;
            String str = bVar2.s;
            if (!com.onetrust.otpublishers.headless.Internal.a.j(str)) {
                c4056l.e.getDrawable().setTint(Color.parseColor(str));
            }
            boolean zOptBoolean = jSONObject.optBoolean("HasConsentOptOut", false);
            String string = jSONObject.getString("CustomGroupId");
            com.onetrust.otpublishers.headless.UI.Helper.c cVar = bVar2.w;
            d(c4056l.c, cVar.a(), cVar);
            com.onetrust.otpublishers.headless.UI.Helper.c cVar2 = bVar2.x;
            bVar.getClass();
            String strOptString = jSONObject.optString("GroupNameMobile");
            if (com.onetrust.otpublishers.headless.Internal.a.j(strOptString)) {
                strOptString = jSONObject.optString("GroupName");
            }
            d(textView, strOptString, cVar2);
            String strM = assistantMode.utils.studiableMetadata.b.m(context, this.n, jSONObject, bVar2.M, bVar2.L);
            boolean zJ = com.onetrust.otpublishers.headless.Internal.a.j(strM);
            TextView textView2 = c4056l.b;
            if (zJ) {
                textView2.setText("");
                i2 = 8;
                textView2.setVisibility(8);
            } else {
                textView2.setVisibility(0);
                h(textView2, strM, bVar2.y);
                i2 = 8;
            }
            com.google.mlkit.common.internal.model.a.i(view, bVar2.t);
            if (c4056l.getAdapterPosition() == 0) {
                OTLogger.c("OT_Automation", 3, "setLineBreakColor PC List: " + bVar2.t);
            }
            f(c4056l, adapterPosition, zOptBoolean);
            switchCompat.setOnCheckedChangeListener(null);
            switchCompat.setOnClickListener(null);
            switchCompat.setContentDescription(bVar2.I);
            textView.setLabelFor(R.id.consent_switch);
            switchCompat.setChecked(oTPublishersHeadlessSDK.getPurposeConsentLocal(string) == 1);
            if (oTPublishersHeadlessSDK.getPurposeConsentLocal(string) == 1) {
                assistantMode.utils.studiableMetadata.b.s(context, switchCompat, this.i, this.j);
            } else {
                assistantMode.utils.studiableMetadata.b.s(context, switchCompat, this.i, this.k);
            }
            switchCompat.setOnClickListener(new ViewOnClickListenerC4054j(this, jSONObject, c4056l, string));
            switchCompat.setOnCheckedChangeListener(new com.onetrust.otpublishers.headless.UI.TVUI.adapter.n(this, jSONObject, c4056l, 1));
            com.onetrust.otpublishers.headless.Internal.Event.a aVar = this.f;
            OTConfiguration oTConfiguration = this.b;
            com.onetrust.otpublishers.headless.UI.fragment.k kVar = new com.onetrust.otpublishers.headless.UI.fragment.k();
            Bundle bundle = new Bundle();
            bundle.putString(OTFragmentTags.FRAGMENT_TAG, OTFragmentTags.OT_PREFERENCE_CENTER_DETAILS_FRAGMENT_TAG);
            kVar.setArguments(bundle);
            kVar.x1 = aVar;
            kVar.J1 = oTConfiguration;
            kVar.L1 = bVar2;
            this.g = kVar;
            kVar.f1 = this;
            kVar.e1 = oTPublishersHeadlessSDK;
            c4056l.itemView.setOnClickListener(new ViewOnClickListenerC4055k(this, adapterPosition, jSONObject, 0));
            view.setVisibility(i != this.d.length() - 1 ? 0 : i2);
        } catch (JSONException e) {
            Z.p("error in rendering groups ", e, "OneTrust", 6);
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final F0 onCreateViewHolder(ViewGroup viewGroup, int i) {
        return new C4056l(Z.c(viewGroup, R.layout.ot_preference_center_item, viewGroup, false));
    }

    @Override // com.onetrust.otpublishers.headless.UI.a
    public final void p(int i) {
        if (i == 4) {
            notifyItemRangeChanged(0, this.d.length());
        }
        com.onetrust.otpublishers.headless.UI.fragment.l lVar = this.a;
        if (lVar != null) {
            lVar.p(i);
        }
    }
}

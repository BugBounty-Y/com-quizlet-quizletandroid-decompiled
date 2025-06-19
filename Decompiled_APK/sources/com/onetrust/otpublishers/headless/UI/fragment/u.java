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
import android.widget.Button;
import android.widget.ImageView;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3705q4;
import com.google.android.gms.measurement.internal.Z;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.onetrust.otpublishers.headless.Public.Keys.OTFragmentTags;
import com.onetrust.otpublishers.headless.Public.OTConsentInteractionType;
import com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK;
import com.onetrust.otpublishers.headless.Public.OTThemeConstants;
import com.quizlet.quizletandroid.R;
import java.util.ArrayList;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public class u extends com.google.android.material.bottomsheet.i implements View.OnClickListener, com.onetrust.otpublishers.headless.UI.a {
    public TextView A;
    public Context B;
    public OTPublishersHeadlessSDK C;
    public JSONObject D;
    public androidx.profileinstaller.a E;
    public com.onetrust.otpublishers.headless.UI.UIProperty.e F;
    public assistantMode.utils.studiableMetadata.b G;
    public com.onetrust.otpublishers.headless.Internal.Helper.k H;
    public RelativeLayout q;
    public TextView r;
    public TextView s;
    public TextView t;
    public View u;
    public View v;
    public Button w;
    public RecyclerView x;
    public com.google.android.material.bottomsheet.h y;
    public ImageView z;

    @Override // com.google.android.material.bottomsheet.i, androidx.appcompat.app.E, androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t
    public final Dialog K(Bundle bundle) {
        Dialog dialogK = super.K(bundle);
        dialogK.setOnShowListener(new com.onetrust.otpublishers.headless.UI.TVUI.fragments.e(this, 10));
        return dialogK;
    }

    @Override // android.view.View.OnClickListener
    public final void onClick(View view) throws JSONException {
        int id = view.getId();
        if (id == R.id.btn_save_consent_preferences) {
            this.C.saveConsent(OTConsentInteractionType.UC_PC_CONFIRM);
            G();
        } else if (id == R.id.close_cp) {
            G();
        }
    }

    @Override // androidx.fragment.app.Fragment, android.content.ComponentCallbacks
    public final void onConfigurationChanged(Configuration configuration) {
        super.onConfigurationChanged(configuration);
        assistantMode.utils.studiableMetadata.b bVar = this.G;
        androidx.fragment.app.I activity = getActivity();
        com.google.android.material.bottomsheet.h hVar = this.y;
        bVar.getClass();
        assistantMode.utils.studiableMetadata.b.z(activity, hVar);
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, androidx.fragment.app.Fragment
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        setRetainInstance(true);
        Context applicationContext = getContext().getApplicationContext();
        if (applicationContext != null && this.C == null) {
            this.C = new OTPublishersHeadlessSDK(applicationContext);
        }
        OTPublishersHeadlessSDK oTPublishersHeadlessSDK = this.C;
        if (oTPublishersHeadlessSDK != null) {
            this.H = oTPublishersHeadlessSDK.getUcpHandler();
        }
        this.G = new assistantMode.utils.studiableMetadata.b(22);
        androidx.fragment.app.I activity = getActivity();
        if (com.google.mlkit.common.internal.model.a.n(activity, OTFragmentTags.OT_UC_PURPOSES_FRAGMENT_TAG)) {
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
        Context context = getContext();
        this.B = context;
        if (com.onetrust.otpublishers.headless.Internal.a.o(context)) {
            layoutInflater = layoutInflater.cloneInContext(new androidx.appcompat.view.d(context, R.style.Theme_AppCompat_Light_NoActionBar));
        }
        View viewInflate = layoutInflater.inflate(R.layout.fragment_ot_uc_purposes, viewGroup, false);
        int iD = assistantMode.utils.studiableMetadata.b.d(this.B, null);
        RecyclerView recyclerView = (RecyclerView) viewInflate.findViewById(R.id.consent_preferences_list);
        this.x = recyclerView;
        recyclerView.setHasFixedSize(true);
        this.x.setLayoutManager(new LinearLayoutManager(getActivity()));
        this.t = (TextView) viewInflate.findViewById(R.id.title);
        this.w = (Button) viewInflate.findViewById(R.id.btn_save_consent_preferences);
        this.s = (TextView) viewInflate.findViewById(R.id.consent_preferences_title);
        this.r = (TextView) viewInflate.findViewById(R.id.consent_preferences_description);
        this.z = (ImageView) viewInflate.findViewById(R.id.close_cp);
        this.u = viewInflate.findViewById(R.id.header_rv_divider);
        this.v = viewInflate.findViewById(R.id.pc_title_divider);
        this.z.setOnClickListener(new com.braze.ui.inappmessage.d(this, 9));
        this.A = (TextView) viewInflate.findViewById(R.id.view_powered_by_logo);
        this.q = (RelativeLayout) viewInflate.findViewById(R.id.uc_purpose_layout);
        this.w.setOnClickListener(this);
        this.z.setOnClickListener(this);
        Context context2 = this.B;
        try {
            this.D = this.C.getPreferenceCenterData();
        } catch (JSONException e) {
            Z.p("Error in PC data initialization. Error msg = ", e, "OTUCPurposesFragment", 6);
        }
        try {
            com.onetrust.otpublishers.headless.UI.UIProperty.f fVar = new com.onetrust.otpublishers.headless.UI.UIProperty.f(context2);
            this.E = fVar.b(this.H, iD);
            this.F = fVar.c(iD);
        } catch (JSONException e2) {
            Z.p("Error in ui property object, error message = ", e2, "OTUCPurposesFragment", 6);
        }
        androidx.profileinstaller.a aVar = this.E;
        if (aVar != null && this.F != null) {
            this.t.setText((String) aVar.e);
            String strOptString = this.F.a;
            if (strOptString == null || com.onetrust.otpublishers.headless.Internal.a.j(strOptString)) {
                strOptString = this.D.optString("PcBackgroundColor");
            }
            this.q.setBackgroundColor(Color.parseColor(strOptString));
            androidx.navigation.internal.m mVar = (androidx.navigation.internal.m) this.E.f;
            androidx.navigation.internal.m mVar2 = this.F.k;
            String strOptString2 = (String) mVar2.b;
            if (strOptString2 == null || com.onetrust.otpublishers.headless.Internal.a.j(strOptString2)) {
                strOptString2 = this.D.optString("PcTextColor");
            }
            this.t.setTextColor(Color.parseColor(strOptString2));
            TextView textView = this.s;
            String strOptString3 = (String) mVar2.b;
            if (strOptString3 == null || com.onetrust.otpublishers.headless.Internal.a.j(strOptString3)) {
                strOptString3 = this.D.optString("PcTextColor");
            }
            textView.setTextColor(Color.parseColor(strOptString3));
            if (!com.onetrust.otpublishers.headless.Internal.a.j((String) ((com.google.android.gms.cloudmessaging.k) mVar2.d).d)) {
                textView.setTextSize(Float.parseFloat((String) ((com.google.android.gms.cloudmessaging.k) mVar2.d).d));
            }
            this.s.setVisibility(mVar.a() ? 0 : 8);
            assistantMode.utils.studiableMetadata.b bVar = this.G;
            Context context3 = this.B;
            TextView textView2 = this.s;
            String str = (String) mVar.g;
            bVar.getClass();
            assistantMode.utils.studiableMetadata.b.r(context3, textView2, str);
            androidx.navigation.internal.m mVar3 = (androidx.navigation.internal.m) this.E.g;
            androidx.navigation.internal.m mVar4 = this.F.l;
            TextView textView3 = this.r;
            String strOptString4 = (String) mVar4.b;
            if (strOptString4 == null || com.onetrust.otpublishers.headless.Internal.a.j(strOptString4)) {
                strOptString4 = this.D.optString("PcTextColor");
            }
            textView3.setTextColor(Color.parseColor(strOptString4));
            if (!com.onetrust.otpublishers.headless.Internal.a.j((String) ((com.google.android.gms.cloudmessaging.k) mVar4.d).d)) {
                textView3.setTextSize(Float.parseFloat((String) ((com.google.android.gms.cloudmessaging.k) mVar4.d).d));
            }
            this.r.setVisibility(mVar3.a() ? 0 : 8);
            assistantMode.utils.studiableMetadata.b bVar2 = this.G;
            Context context4 = this.B;
            TextView textView4 = this.r;
            String str2 = (String) mVar3.g;
            bVar2.getClass();
            assistantMode.utils.studiableMetadata.b.r(context4, textView4, str2);
            this.A.setVisibility(this.E.c ? 0 : 8);
            TextView textView5 = this.A;
            String strOptString5 = (String) mVar4.b;
            if (strOptString5 == null || com.onetrust.otpublishers.headless.Internal.a.j(strOptString5)) {
                strOptString5 = this.D.optString("PcTextColor");
            }
            textView5.setTextColor(Color.parseColor(strOptString5));
            if (!com.onetrust.otpublishers.headless.Internal.a.j((String) ((com.google.android.gms.cloudmessaging.k) mVar4.d).d)) {
                textView5.setTextSize(Float.parseFloat((String) ((com.google.android.gms.cloudmessaging.k) mVar4.d).d));
            }
            this.A.setText(requireContext().getString(R.string.ot_powered_by_one_trust));
            if (((ArrayList) this.E.i).size() == 0) {
                this.u.setVisibility(8);
            }
            String str3 = this.F.b;
            if (!com.onetrust.otpublishers.headless.Internal.a.j(str3)) {
                this.u.setBackgroundColor(Color.parseColor(str3));
                this.v.setBackgroundColor(Color.parseColor(str3));
            }
            this.x.setAdapter(new com.onetrust.otpublishers.headless.UI.TVUI.adapter.l(this.B, this.E, this.F, this.D.optString("PcTextColor"), this, this.H));
            androidx.constraintlayout.motion.widget.n nVar = (androidx.constraintlayout.motion.widget.n) this.E.h;
            androidx.constraintlayout.motion.widget.n nVar2 = this.F.y;
            Button button = this.w;
            button.setText((String) nVar2.j);
            com.google.android.gms.cloudmessaging.k kVar = (com.google.android.gms.cloudmessaging.k) nVar2.d;
            if (!com.onetrust.otpublishers.headless.Internal.a.j((String) kVar.d)) {
                button.setTextSize(Float.parseFloat((String) kVar.d));
            }
            button.setTextColor(Color.parseColor(!com.onetrust.otpublishers.headless.Internal.a.j((String) nVar2.f) ? (String) nVar2.f : this.D.optString("PcButtonTextColor")));
            assistantMode.utils.studiableMetadata.b.q(this.B, button, nVar2, !com.onetrust.otpublishers.headless.Internal.a.j((String) nVar2.e) ? (String) nVar2.e : this.D.optString("PcButtonColor"), (String) nVar2.g);
            this.w.setText(nVar.a());
            String strOptString6 = (String) this.F.z.f;
            if (com.onetrust.otpublishers.headless.Internal.a.j(strOptString6) && ((strOptString6 = (String) this.F.l.b) == null || com.onetrust.otpublishers.headless.Internal.a.j(strOptString6))) {
                strOptString6 = this.D.optString("PcTextColor");
            }
            this.z.setColorFilter(Color.parseColor(strOptString6));
        }
        return viewInflate;
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t
    public final void p(int i) {
        if (i == 1) {
            G();
        }
    }
}

package com.onetrust.otpublishers.headless.UI.fragment;

import android.app.Dialog;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.res.Configuration;
import android.graphics.Color;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.RelativeLayout;
import android.widget.TextView;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3649j4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3705q4;
import com.google.android.gms.measurement.internal.Z;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.onetrust.otpublishers.headless.Public.DataModel.OTConfiguration;
import com.onetrust.otpublishers.headless.Public.DataModel.OTCustomConfigurator;
import com.onetrust.otpublishers.headless.Public.DataModel.OTProxyType;
import com.onetrust.otpublishers.headless.Public.Keys.OTFragmentTags;
import com.onetrust.otpublishers.headless.Public.OTConsentUICallback;
import com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK;
import com.onetrust.otpublishers.headless.Public.OTThemeConstants;
import com.quizlet.quizletandroid.R;
import java.net.MalformedURLException;
import java.net.URL;
import org.json.JSONException;

/* renamed from: com.onetrust.otpublishers.headless.UI.fragment.b, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public class ViewOnClickListenerC4058b extends com.google.android.material.bottomsheet.i implements View.OnClickListener, com.onetrust.otpublishers.headless.UI.a {
    public OTConfiguration A;
    public OTPublishersHeadlessSDK B;
    public androidx.profileinstaller.a C;
    public OTConsentUICallback D;
    public Context q;
    public TextView r;
    public TextView s;
    public Button t;
    public Button u;
    public ImageView v;
    public com.google.android.material.bottomsheet.h w;
    public RelativeLayout x;
    public TextView y;
    public assistantMode.utils.studiableMetadata.b z;

    @Override // com.google.android.material.bottomsheet.i, androidx.appcompat.app.E, androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t
    public final Dialog K(Bundle bundle) {
        Dialog dialogK = super.K(bundle);
        dialogK.setOnShowListener(new com.onetrust.otpublishers.headless.UI.TVUI.fragments.e(this, 1));
        return dialogK;
    }

    public final void Q(Button button, androidx.constraintlayout.motion.widget.n nVar, int i, int i2) {
        com.google.android.gms.cloudmessaging.k kVar = (com.google.android.gms.cloudmessaging.k) nVar.d;
        assistantMode.utils.studiableMetadata.b bVar = this.z;
        OTConfiguration oTConfiguration = this.A;
        bVar.getClass();
        assistantMode.utils.studiableMetadata.b.u(button, kVar, oTConfiguration);
        if (!com.onetrust.otpublishers.headless.Internal.a.j((String) kVar.d)) {
            button.setTextSize(Float.parseFloat((String) kVar.d));
        }
        button.setText((String) nVar.j);
        if (!com.onetrust.otpublishers.headless.Internal.a.j((String) nVar.f)) {
            i2 = Color.parseColor((String) nVar.f);
        } else if (button.equals(this.u)) {
            i2 = this.q.getColor(R.color.blackOT);
        }
        button.setTextColor(i2);
        if (!com.onetrust.otpublishers.headless.Internal.a.j((String) nVar.e)) {
            assistantMode.utils.studiableMetadata.b.q(this.q, button, nVar, (String) nVar.e, (String) nVar.g);
            return;
        }
        if (!button.equals(this.u)) {
            button.setBackgroundColor(i);
            return;
        }
        GradientDrawable gradientDrawable = new GradientDrawable();
        gradientDrawable.setShape(0);
        gradientDrawable.setStroke(Integer.parseInt("3"), this.q.getColor(R.color.blackOT));
        gradientDrawable.setColor(this.q.getColor(R.color.whiteOT));
        button.setBackground(gradientDrawable);
    }

    public final void a() throws NumberFormatException {
        RelativeLayout relativeLayout;
        int color;
        String proxyDomainURLString;
        androidx.profileinstaller.a aVar = this.C;
        if (aVar != null) {
            if (com.onetrust.otpublishers.headless.Internal.a.j((String) aVar.e)) {
                relativeLayout = this.x;
                color = this.q.getColor(R.color.whiteOT);
            } else {
                relativeLayout = this.x;
                color = Color.parseColor((String) this.C.e);
            }
            relativeLayout.setBackgroundColor(color);
            int color2 = this.q.getColor(R.color.groupItemSelectedBGOT);
            int color3 = this.q.getColor(R.color.whiteOT);
            androidx.navigation.internal.m mVar = (androidx.navigation.internal.m) this.C.f;
            String str = !com.onetrust.otpublishers.headless.Internal.a.j((String) mVar.b) ? (String) mVar.b : "";
            TextView textView = this.r;
            com.google.android.gms.cloudmessaging.k kVar = (com.google.android.gms.cloudmessaging.k) mVar.d;
            textView.setText((String) mVar.g);
            com.google.android.gms.cloudmessaging.k kVar2 = (com.google.android.gms.cloudmessaging.k) mVar.d;
            assistantMode.utils.studiableMetadata.b bVar = this.z;
            OTConfiguration oTConfiguration = this.A;
            bVar.getClass();
            assistantMode.utils.studiableMetadata.b.w(textView, kVar2, oTConfiguration);
            if (!com.onetrust.otpublishers.headless.Internal.a.j((String) kVar.d)) {
                textView.setTextSize(Float.parseFloat((String) kVar.d));
            }
            assistantMode.utils.studiableMetadata.b.x(textView, (String) mVar.f);
            textView.setTextColor(!com.onetrust.otpublishers.headless.Internal.a.j(str) ? Color.parseColor(str) : this.q.getColor(R.color.blackOT));
            androidx.navigation.internal.m mVar2 = (androidx.navigation.internal.m) this.C.g;
            String str2 = com.onetrust.otpublishers.headless.Internal.a.j((String) mVar2.b) ? "" : (String) mVar2.b;
            TextView textView2 = this.s;
            com.google.android.gms.cloudmessaging.k kVar3 = (com.google.android.gms.cloudmessaging.k) mVar2.d;
            textView2.setText((String) mVar2.g);
            com.google.android.gms.cloudmessaging.k kVar4 = (com.google.android.gms.cloudmessaging.k) mVar2.d;
            assistantMode.utils.studiableMetadata.b bVar2 = this.z;
            OTConfiguration oTConfiguration2 = this.A;
            bVar2.getClass();
            assistantMode.utils.studiableMetadata.b.w(textView2, kVar4, oTConfiguration2);
            if (!com.onetrust.otpublishers.headless.Internal.a.j((String) kVar3.d)) {
                textView2.setTextSize(Float.parseFloat((String) kVar3.d));
            }
            assistantMode.utils.studiableMetadata.b.x(textView2, (String) mVar2.f);
            textView2.setTextColor(!com.onetrust.otpublishers.headless.Internal.a.j(str2) ? Color.parseColor(str2) : this.q.getColor(R.color.blackOT));
            Q(this.t, (androidx.constraintlayout.motion.widget.n) this.C.h, color2, color3);
            Q(this.u, (androidx.constraintlayout.motion.widget.n) this.C.i, color2, color3);
            androidx.profileinstaller.a aVar2 = this.C;
            if (!aVar2.c) {
                this.v.getLayoutParams().height = 20;
                return;
            }
            String str3 = (String) aVar2.d;
            if (com.onetrust.otpublishers.headless.Internal.a.j(str3)) {
                this.v.setImageResource(R.drawable.ic_ag);
                return;
            }
            try {
                proxyDomainURLString = OTCustomConfigurator.getProxyDomainURLString(new OTProxyType.AgeGateLogo(new URL(str3)));
            } catch (MalformedURLException e) {
                OTLogger.c("OTAgeGateFragment", 6, "Error while fetching age gate logo using proxy" + e.getMessage());
                proxyDomainURLString = null;
            }
            AbstractC3649j4.a(R.drawable.ic_ag, this.v, proxyDomainURLString, str3, "Age Gate Prompt");
        }
    }

    @Override // android.view.View.OnClickListener
    public final void onClick(View view) {
        OTConsentUICallback oTConsentUICallback;
        int id = view.getId();
        com.onetrust.otpublishers.headless.Internal.Helper.b bVar = new com.onetrust.otpublishers.headless.Internal.Helper.b(this.q);
        if (id == R.id.btn_accept) {
            bVar.a("OPT_IN");
            G();
            OTLogger.c("OTAgeGateFragment", 3, "Age-Gate Consent Status: " + this.B.getAgeGatePromptValue());
            oTConsentUICallback = this.D;
            if (oTConsentUICallback == null) {
                return;
            }
        } else {
            if (id != R.id.btn_not_now) {
                return;
            }
            bVar.a("OPT_OUT");
            G();
            OTLogger.c("OTAgeGateFragment", 3, "Age-Gate Consent Status: " + this.B.getAgeGatePromptValue());
            oTConsentUICallback = this.D;
            if (oTConsentUICallback == null) {
                return;
            }
        }
        oTConsentUICallback.onCompletion();
    }

    @Override // androidx.fragment.app.Fragment, android.content.ComponentCallbacks
    public final void onConfigurationChanged(Configuration configuration) {
        super.onConfigurationChanged(configuration);
        assistantMode.utils.studiableMetadata.b bVar = this.z;
        androidx.fragment.app.I activity = getActivity();
        com.google.android.material.bottomsheet.h hVar = this.w;
        bVar.getClass();
        assistantMode.utils.studiableMetadata.b.z(activity, hVar);
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, androidx.fragment.app.Fragment
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        setRetainInstance(true);
        this.B = new OTPublishersHeadlessSDK(getContext().getApplicationContext());
        androidx.fragment.app.I activity = getActivity();
        if (com.google.mlkit.common.internal.model.a.n(activity, OTFragmentTags.OT_AGE_GATE_FRAGMENT_TAG)) {
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
    public final View onCreateView(LayoutInflater layoutInflater, ViewGroup viewGroup, Bundle bundle) throws NumberFormatException {
        this.q = getContext();
        com.onetrust.otpublishers.headless.UI.mobiledatautils.b bVar = new com.onetrust.otpublishers.headless.UI.mobiledatautils.b();
        if (!bVar.j(assistantMode.utils.studiableMetadata.b.d(this.q, this.A), this.q, this.B)) {
            G();
            return null;
        }
        this.z = new assistantMode.utils.studiableMetadata.b(22);
        View viewJ = assistantMode.utils.studiableMetadata.b.j(this.q, layoutInflater, viewGroup, R.layout.fragment_ot_age_gate);
        this.t = (Button) viewJ.findViewById(R.id.btn_accept);
        this.u = (Button) viewJ.findViewById(R.id.btn_not_now);
        this.x = (RelativeLayout) viewJ.findViewById(R.id.age_gate_parent_layout);
        this.r = (TextView) viewJ.findViewById(R.id.age_gate_title);
        this.s = (TextView) viewJ.findViewById(R.id.age_gate_description);
        this.v = (ImageView) viewJ.findViewById(R.id.age_gate_logo);
        this.y = (TextView) viewJ.findViewById(R.id.view_powered_by_logo);
        this.t.setOnClickListener(this);
        this.u.setOnClickListener(this);
        try {
            this.C = new com.onetrust.otpublishers.headless.UI.UIProperty.f(this.q).a();
        } catch (JSONException e) {
            Z.p("Error in ui property object, error message = ", e, "OTAgeGateFragment", 6);
        }
        try {
            a();
            bVar.c(this.y, this.A);
        } catch (JSONException e2) {
            Z.p("error while populating Age-Gate UI ", e2, "OTAgeGateFragment", 6);
        }
        return viewJ;
    }
}

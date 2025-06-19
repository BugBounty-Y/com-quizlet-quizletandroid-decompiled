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
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.google.android.gms.internal.mlkit_vision_document_scanner.W;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.onetrust.otpublishers.headless.Public.Keys.OTFragmentTags;
import com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK;
import com.onetrust.otpublishers.headless.Public.OTThemeConstants;
import com.quizlet.quizletandroid.R;
import java.util.ArrayList;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public class v extends com.google.android.material.bottomsheet.i {
    public String A;
    public String B;
    public String C;
    public assistantMode.utils.studiableMetadata.b E;
    public int F;
    public com.onetrust.otpublishers.headless.Internal.Helper.k G;
    public boolean H;
    public JSONObject K;
    public com.onetrust.otpublishers.headless.UI.UIProperty.e L;
    public RelativeLayout M;
    public View V;
    public TextView q;
    public TextView r;
    public TextView s;
    public TextView t;
    public RecyclerView u;
    public com.google.android.material.bottomsheet.h v;
    public ImageView w;
    public TextView x;
    public com.onetrust.otpublishers.headless.UI.adapter.B y;
    public OTPublishersHeadlessSDK z;
    public final com.onetrust.otpublishers.headless.Internal.Event.a D = new com.onetrust.otpublishers.headless.Internal.Event.a();
    public ArrayList I = new ArrayList();
    public ArrayList J = new ArrayList();

    @Override // com.google.android.material.bottomsheet.i, androidx.appcompat.app.E, androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t
    public final Dialog K(Bundle bundle) {
        Dialog dialogK = super.K(bundle);
        dialogK.setOnShowListener(new com.onetrust.otpublishers.headless.UI.TVUI.fragments.e(this, 11));
        return dialogK;
    }

    @Override // androidx.fragment.app.Fragment, android.content.ComponentCallbacks
    public final void onConfigurationChanged(Configuration configuration) {
        super.onConfigurationChanged(configuration);
        assistantMode.utils.studiableMetadata.b bVar = this.E;
        androidx.fragment.app.I activity = getActivity();
        com.google.android.material.bottomsheet.h hVar = this.v;
        bVar.getClass();
        assistantMode.utils.studiableMetadata.b.z(activity, hVar);
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, androidx.fragment.app.Fragment
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        setRetainInstance(true);
        Context applicationContext = getContext().getApplicationContext();
        if (applicationContext != null && this.z == null) {
            this.z = new OTPublishersHeadlessSDK(applicationContext);
        }
        this.E = new assistantMode.utils.studiableMetadata.b(22);
        try {
            this.K = this.z.getPreferenceCenterData();
        } catch (JSONException e) {
            W.a("error while fetching PC Data ", e, "UCPPurposeDetails", 6);
        }
        if (getArguments() != null) {
            if (getArguments().getParcelableArrayList("CUSTOM_PREF_ARRAY") != null) {
                this.J = getArguments().getParcelableArrayList("CUSTOM_PREF_ARRAY");
            } else if (getArguments().getParcelableArrayList("TOPIC_PREF_ARRAY") != null) {
                this.I = getArguments().getParcelableArrayList("TOPIC_PREF_ARRAY");
            }
            this.A = getArguments().getString("ITEM_LABEL");
            this.B = getArguments().getString("ITEM_DESC");
            this.F = getArguments().getInt("ITEM_POSITION");
            this.C = getArguments().getString("TITLE_TEXT_COLOR");
            this.H = getArguments().getBoolean("PURPOSE_TOGGLE_STATE");
        }
        androidx.fragment.app.I activity = getActivity();
        if (com.google.mlkit.common.internal.model.a.n(activity, OTFragmentTags.OT_UC_PURPOSES_FRAGMENT_TAG)) {
            SharedPreferences sharedPreferences = activity.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOT_SDK_APP_CONFIGURATION", 0);
            String str = OTThemeConstants.NO_SDK_THEME_OVERRIDE;
            String string = sharedPreferences.getString("OT_UX_SDK_THEME", OTThemeConstants.NO_SDK_THEME_OVERRIDE);
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
        LayoutInflater layoutInflaterCloneInContext = layoutInflater;
        Context context = getContext();
        if (com.onetrust.otpublishers.headless.Internal.a.o(context)) {
            layoutInflaterCloneInContext = layoutInflaterCloneInContext.cloneInContext(new androidx.appcompat.view.d(context, R.style.Theme_AppCompat_Light_NoActionBar));
        }
        View viewInflate = layoutInflaterCloneInContext.inflate(R.layout.fragment_ot_uc_purposes_options, viewGroup, false);
        try {
            this.L = new com.onetrust.otpublishers.headless.UI.UIProperty.f(context).c(assistantMode.utils.studiableMetadata.b.d(context, null));
        } catch (JSONException e) {
            e.printStackTrace();
        }
        this.q = (TextView) viewInflate.findViewById(R.id.title);
        this.r = (TextView) viewInflate.findViewById(R.id.selected_item_title);
        this.s = (TextView) viewInflate.findViewById(R.id.selected_item_description);
        this.t = (TextView) viewInflate.findViewById(R.id.list_title);
        RecyclerView recyclerView = (RecyclerView) viewInflate.findViewById(R.id.consent_preferences_selection_list);
        this.u = recyclerView;
        recyclerView.setHasFixedSize(true);
        this.u.setLayoutManager(new LinearLayoutManager(getActivity()));
        this.w = (ImageView) viewInflate.findViewById(R.id.back_cp);
        this.x = (TextView) viewInflate.findViewById(R.id.view_powered_by_logo);
        this.M = (RelativeLayout) viewInflate.findViewById(R.id.option_main_layout);
        this.V = viewInflate.findViewById(R.id.pc_title_divider);
        this.w.setOnClickListener(new com.braze.ui.inappmessage.d(this, 10));
        this.r.setText(this.A);
        this.s.setText(this.B);
        String str = this.L.a;
        String strOptString = this.K.optString("PcBackgroundColor");
        if (com.onetrust.otpublishers.headless.Internal.a.j(str)) {
            str = strOptString;
        }
        com.onetrust.otpublishers.headless.UI.UIProperty.e eVar = this.L;
        androidx.navigation.internal.m mVar = eVar.t;
        androidx.navigation.internal.m mVar2 = eVar.l;
        String str2 = (String) mVar.b;
        String str3 = com.onetrust.otpublishers.headless.Internal.a.j(str2) ? this.C : str2;
        String str4 = (String) this.L.k.b;
        String str5 = this.C;
        if (com.onetrust.otpublishers.headless.Internal.a.j(str4)) {
            str4 = str5;
        }
        String str6 = (String) mVar2.b;
        String str7 = this.C;
        if (com.onetrust.otpublishers.headless.Internal.a.j(str6)) {
            str6 = str7;
        }
        TextView textView = this.r;
        if (!com.onetrust.otpublishers.headless.Internal.a.j(str3)) {
            textView.setTextColor(Color.parseColor(str3));
        }
        String str8 = (String) ((com.google.android.gms.cloudmessaging.k) mVar.d).d;
        if (!com.onetrust.otpublishers.headless.Internal.a.j(str8)) {
            textView.setTextSize(Float.parseFloat(str8));
        }
        TextView textView2 = this.s;
        if (!com.onetrust.otpublishers.headless.Internal.a.j(str3)) {
            textView2.setTextColor(Color.parseColor(str3));
        }
        String str9 = (String) ((com.google.android.gms.cloudmessaging.k) mVar2.d).d;
        if (!com.onetrust.otpublishers.headless.Internal.a.j(str9)) {
            textView2.setTextSize(Float.parseFloat(str9));
        }
        TextView textView3 = this.t;
        if (!com.onetrust.otpublishers.headless.Internal.a.j(str3)) {
            textView3.setTextColor(Color.parseColor(str3));
        }
        String str10 = (String) ((com.google.android.gms.cloudmessaging.k) mVar2.d).d;
        if (!com.onetrust.otpublishers.headless.Internal.a.j(str10)) {
            textView3.setTextSize(Float.parseFloat(str10));
        }
        this.q.setTextColor(Color.parseColor(str4));
        this.w.setColorFilter(Color.parseColor(str4));
        this.M.setBackgroundColor(Color.parseColor(str));
        this.x.setVisibility(this.L.i ? 0 : 8);
        TextView textView4 = this.x;
        if (!com.onetrust.otpublishers.headless.Internal.a.j(str6)) {
            textView4.setTextColor(Color.parseColor(str6));
        }
        String str11 = (String) ((com.google.android.gms.cloudmessaging.k) mVar2.d).d;
        if (!com.onetrust.otpublishers.headless.Internal.a.j(str11)) {
            textView4.setTextSize(Float.parseFloat(str11));
        }
        String str12 = this.L.b;
        if (!com.onetrust.otpublishers.headless.Internal.a.j(str12)) {
            this.V.setBackgroundColor(Color.parseColor(str12));
        }
        if (this.J.size() > 0) {
            this.t.setText(((com.onetrust.otpublishers.headless.UI.DataModels.b) this.J.get(this.F)).b);
            this.q.setText(((com.onetrust.otpublishers.headless.UI.DataModels.b) this.J.get(this.F)).b);
            this.y = new com.onetrust.otpublishers.headless.UI.adapter.B(((com.onetrust.otpublishers.headless.UI.DataModels.b) this.J.get(this.F)).f, "customPrefOptionType", ((com.onetrust.otpublishers.headless.UI.DataModels.b) this.J.get(this.F)).d, this.G, this.H, str3, this.L);
        } else if (this.I.size() > 0) {
            this.t.setText(((com.onetrust.otpublishers.headless.UI.DataModels.e) this.I.get(this.F)).a);
            this.q.setText(((com.onetrust.otpublishers.headless.UI.DataModels.e) this.I.get(this.F)).a);
            this.y = new com.onetrust.otpublishers.headless.UI.adapter.B(((com.onetrust.otpublishers.headless.UI.DataModels.e) this.I.get(this.F)).b, "topicOptionType", "null", this.G, this.H, str3, this.L);
        }
        this.u.setAdapter(this.y);
        return viewInflate;
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, androidx.fragment.app.Fragment
    public final void onDestroyView() {
        super.onDestroyView();
    }
}

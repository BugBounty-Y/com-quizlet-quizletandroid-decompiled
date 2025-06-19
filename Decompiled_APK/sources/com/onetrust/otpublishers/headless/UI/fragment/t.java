package com.onetrust.otpublishers.headless.UI.fragment;

import android.app.Dialog;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.res.Configuration;
import android.graphics.Color;
import android.graphics.Typeface;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.google.android.gms.internal.ads.Yh;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3705q4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.P;
import com.google.android.gms.measurement.internal.Z;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.onetrust.otpublishers.headless.Public.DataModel.OTConfiguration;
import com.onetrust.otpublishers.headless.Public.Keys.OTFragmentTags;
import com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK;
import com.onetrust.otpublishers.headless.Public.OTThemeConstants;
import com.quizlet.quizletandroid.R;
import java.util.ArrayList;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public class t extends com.google.android.material.bottomsheet.i implements View.OnClickListener {
    public List A = new ArrayList();
    public List B = new ArrayList();
    public Yh C;
    public View D;
    public OTConfiguration E;
    public com.google.mlkit.common.internal.model.a F;
    public TextView q;
    public RecyclerView r;
    public Button s;
    public com.google.android.material.bottomsheet.h t;
    public com.onetrust.otpublishers.headless.UI.adapter.o u;
    public RelativeLayout v;
    public Context w;
    public RelativeLayout x;
    public OTPublishersHeadlessSDK y;
    public n z;

    @Override // com.google.android.material.bottomsheet.i, androidx.appcompat.app.E, androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t
    public final Dialog K(Bundle bundle) {
        Dialog dialogK = super.K(bundle);
        dialogK.setOnShowListener(new com.onetrust.otpublishers.headless.UI.TVUI.fragments.e(this, 9));
        return dialogK;
    }

    @Override // android.view.View.OnClickListener
    public final void onClick(View view) {
        int id = view.getId();
        if (id != R.id.btn_apply_filter) {
            if (id == R.id.ot_cancel_filter) {
                this.B = this.A;
                G();
                return;
            }
            return;
        }
        boolean zIsEmpty = ((ArrayList) this.u.d).isEmpty();
        n nVar = this.z;
        ArrayList selectedList = (ArrayList) this.u.d;
        s this$0 = nVar.a;
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(selectedList, "selectedCategories");
        com.onetrust.otpublishers.headless.UI.viewmodel.d dVarS = this$0.S();
        dVarS.getClass();
        Intrinsics.checkNotNullParameter(selectedList, "selectedList");
        dVarS.q.l(selectedList);
        this$0.S().i = zIsEmpty;
        this$0.S().B();
        this$0.Q(Boolean.valueOf(zIsEmpty));
        boolean zC = this$0.S().C();
        if (!Boolean.parseBoolean(this$0.S().f)) {
            zC = false;
        }
        this$0.R(zC);
        G();
    }

    @Override // androidx.fragment.app.Fragment, android.content.ComponentCallbacks
    public final void onConfigurationChanged(Configuration configuration) {
        super.onConfigurationChanged(configuration);
        com.google.mlkit.common.internal.model.a aVar = this.F;
        Context context = this.w;
        com.google.android.material.bottomsheet.h hVar = this.t;
        aVar.getClass();
        com.google.mlkit.common.internal.model.a.g(context, hVar);
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, androidx.fragment.app.Fragment
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        setRetainInstance(true);
        if (this.y == null) {
            G();
        }
        androidx.fragment.app.I activity = getActivity();
        if (com.google.mlkit.common.internal.model.a.n(activity, OTFragmentTags.OT_SDK_LIST_FILTER_FRAGMENT_TAG)) {
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
        Typeface typeface;
        Typeface otTypeFaceMap;
        Typeface otTypeFaceMap2;
        Context context = getContext();
        this.w = context;
        this.F = new com.google.mlkit.common.internal.model.a(22);
        int iD = assistantMode.utils.studiableMetadata.b.d(context, this.E);
        androidx.work.impl.model.l lVar = new androidx.work.impl.model.l(14);
        lVar.g(iD, this.w, this.y);
        this.C = (Yh) lVar.b;
        Context context2 = this.w;
        if (com.onetrust.otpublishers.headless.Internal.a.o(context2)) {
            layoutInflater = layoutInflater.cloneInContext(new androidx.appcompat.view.d(context2, R.style.Theme_AppCompat_Light_NoActionBar));
        }
        View viewInflate = layoutInflater.inflate(R.layout.fragment_ot_sdk_list_filter, viewGroup, false);
        com.google.mlkit.common.internal.model.a.f(this.w, viewInflate, "OTSDKListFragment");
        RecyclerView recyclerView = (RecyclerView) viewInflate.findViewById(R.id.filter_list);
        this.r = recyclerView;
        recyclerView.setHasFixedSize(true);
        this.r.setLayoutManager(new LinearLayoutManager(getActivity()));
        this.q = (TextView) viewInflate.findViewById(R.id.ot_cancel_filter);
        this.x = (RelativeLayout) viewInflate.findViewById(R.id.footer_layout);
        this.s = (Button) viewInflate.findViewById(R.id.btn_apply_filter);
        this.v = (RelativeLayout) viewInflate.findViewById(R.id.filter_layout);
        this.D = viewInflate.findViewById(R.id.view1);
        this.s.setOnClickListener(this);
        this.q.setOnClickListener(this);
        JSONArray jSONArrayG = P.g((JSONObject) lVar.c);
        JSONArray jSONArray = new JSONArray();
        for (int i = 0; i < jSONArrayG.length(); i++) {
            try {
                androidx.work.impl.model.l.h(i, jSONArrayG, jSONArray, new JSONObject());
            } catch (JSONException e) {
                Z.p("Error on parsing Categories list. Error msg = ", e, "OTSDKListFilter", 6);
            }
        }
        com.onetrust.otpublishers.headless.UI.adapter.o oVar = new com.onetrust.otpublishers.headless.UI.adapter.o(jSONArray, this.B, this.E, lVar, this);
        this.u = oVar;
        this.r.setAdapter(oVar);
        Yh yh = this.C;
        if (yh != null) {
            String str = (String) yh.b;
            this.v.setBackgroundColor(Color.parseColor(str));
            this.x.setBackgroundColor(Color.parseColor(str));
            androidx.navigation.internal.m mVar = (androidx.navigation.internal.m) this.C.l;
            TextView textView = this.q;
            textView.setText((String) mVar.g);
            com.google.android.gms.cloudmessaging.k kVar = (com.google.android.gms.cloudmessaging.k) mVar.d;
            OTConfiguration oTConfiguration = this.E;
            String str2 = (String) kVar.e;
            if (com.onetrust.otpublishers.headless.Internal.a.j(str2) || oTConfiguration == null || (otTypeFaceMap2 = oTConfiguration.getOtTypeFaceMap(str2)) == null) {
                int iA = com.google.android.gms.cloudmessaging.k.a(textView, kVar.b);
                textView.setTypeface(!com.onetrust.otpublishers.headless.Internal.a.j((String) kVar.c) ? Typeface.create((String) kVar.c, iA) : Typeface.create(textView.getTypeface(), iA));
            } else {
                textView.setTypeface(otTypeFaceMap2);
            }
            if (!com.onetrust.otpublishers.headless.Internal.a.j((String) kVar.d)) {
                textView.setTextSize(Float.parseFloat((String) kVar.d));
            }
            if (!com.onetrust.otpublishers.headless.Internal.a.j((String) mVar.b)) {
                textView.setTextColor(Color.parseColor((String) mVar.b));
            }
            assistantMode.utils.studiableMetadata.b.x(textView, (String) mVar.f);
            androidx.constraintlayout.motion.widget.n nVar = (androidx.constraintlayout.motion.widget.n) this.C.n;
            Button button = this.s;
            button.setText((String) nVar.j);
            com.google.android.gms.cloudmessaging.k kVar2 = (com.google.android.gms.cloudmessaging.k) nVar.d;
            OTConfiguration oTConfiguration2 = this.E;
            String str3 = (String) kVar2.e;
            if (com.onetrust.otpublishers.headless.Internal.a.j(str3) || oTConfiguration2 == null || (otTypeFaceMap = oTConfiguration2.getOtTypeFaceMap(str3)) == null) {
                int style = kVar2.b;
                if (style == -1 && (typeface = button.getTypeface()) != null) {
                    style = typeface.getStyle();
                }
                button.setTypeface(!com.onetrust.otpublishers.headless.Internal.a.j((String) kVar2.c) ? Typeface.create((String) kVar2.c, style) : Typeface.create(button.getTypeface(), style));
            } else {
                button.setTypeface(otTypeFaceMap);
            }
            if (!com.onetrust.otpublishers.headless.Internal.a.j((String) kVar2.d)) {
                button.setTextSize(Float.parseFloat((String) kVar2.d));
            }
            if (!com.onetrust.otpublishers.headless.Internal.a.j((String) nVar.f)) {
                button.setTextColor(Color.parseColor((String) nVar.f));
            }
            assistantMode.utils.studiableMetadata.b.q(this.w, button, nVar, (String) nVar.e, (String) nVar.g);
            String str4 = (String) this.C.c;
            if (!com.onetrust.otpublishers.headless.Internal.a.j(str4)) {
                this.D.setBackgroundColor(Color.parseColor(str4));
            }
        }
        return viewInflate;
    }
}

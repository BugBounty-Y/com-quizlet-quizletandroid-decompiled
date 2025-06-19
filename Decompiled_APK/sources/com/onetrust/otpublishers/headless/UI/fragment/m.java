package com.onetrust.otpublishers.headless.UI.fragment;

import android.app.Dialog;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.res.Configuration;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.recyclerview.widget.RecyclerView;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3705q4;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.onetrust.otpublishers.headless.Public.DataModel.OTConfiguration;
import com.onetrust.otpublishers.headless.Public.Keys.OTFragmentTags;
import com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK;
import com.onetrust.otpublishers.headless.Public.OTThemeConstants;
import com.quizlet.quizletandroid.R;
import java.util.HashMap;
import java.util.Map;

/* loaded from: classes2.dex */
public class m extends com.google.android.material.bottomsheet.i implements View.OnClickListener, com.onetrust.otpublishers.headless.UI.a {
    public Map A;
    public Map B;
    public com.onetrust.otpublishers.headless.UI.UIProperty.g C;
    public OTConfiguration D;
    public View E;
    public com.google.mlkit.common.internal.model.a F;
    public String G;
    public TextView q;
    public RecyclerView r;
    public Button s;
    public com.google.android.material.bottomsheet.h t;
    public com.onetrust.otpublishers.headless.UI.adapter.o u;
    public RelativeLayout v;
    public Context w;
    public RelativeLayout x;
    public OTPublishersHeadlessSDK y;
    public w z;

    @Override // com.google.android.material.bottomsheet.i, androidx.appcompat.app.E, androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t
    public final Dialog K(Bundle bundle) {
        Dialog dialogK = super.K(bundle);
        dialogK.setOnShowListener(new com.onetrust.otpublishers.headless.UI.TVUI.fragments.e(this, 7));
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
        w wVar = this.z;
        com.onetrust.otpublishers.headless.UI.adapter.o oVar = this.u;
        OTLogger.c("OneTrust", 4, "Purposes to pass on apply filters : " + ((HashMap) oVar.e));
        wVar.a((HashMap) oVar.e);
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
        if (com.google.mlkit.common.internal.model.a.n(activity, OTFragmentTags.OT_VENDOR_LIST_FILTER_FRAGMENT_TAG)) {
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

    /* JADX WARN: Removed duplicated region for block: B:61:0x019f  */
    /* JADX WARN: Removed duplicated region for block: B:81:0x0205 A[Catch: JSONException -> 0x0219, TryCatch #1 {JSONException -> 0x0219, blocks: (B:78:0x01fb, B:79:0x01ff, B:81:0x0205, B:83:0x0215), top: B:139:0x01fb }] */
    /* JADX WARN: Removed duplicated region for block: B:90:0x0236  */
    /* JADX WARN: Removed duplicated region for block: B:93:0x0254  */
    @Override // androidx.fragment.app.Fragment
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final android.view.View onCreateView(android.view.LayoutInflater r18, android.view.ViewGroup r19, android.os.Bundle r20) throws org.json.JSONException, java.lang.NumberFormatException {
        /*
            Method dump skipped, instructions count: 911
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.UI.fragment.m.onCreateView(android.view.LayoutInflater, android.view.ViewGroup, android.os.Bundle):android.view.View");
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t
    public final void p(int i) {
        if (i == 1) {
            w wVar = this.z;
            com.onetrust.otpublishers.headless.UI.adapter.o oVar = this.u;
            OTLogger.c("OneTrust", 4, "Purposes to pass on apply filters : " + ((HashMap) oVar.e));
            wVar.a((HashMap) oVar.e);
            G();
        }
    }
}

package com.onetrust.otpublishers.headless.UI.TVUI.fragments;

import android.content.Context;
import android.content.SharedPreferences;
import android.graphics.Color;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.view.KeyEvent;
import android.view.View;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.camera.camera2.internal.c0;
import androidx.compose.ui.platform.X0;
import androidx.fragment.app.AbstractC1136h0;
import androidx.fragment.app.C1121a;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.I;
import androidx.recyclerview.widget.RecyclerView;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3617f4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.P;
import com.google.android.gms.internal.mlkit_vision_document_scanner.Q;
import com.google.android.gms.internal.mlkit_vision_document_scanner.W;
import com.google.android.gms.measurement.internal.Z;
import com.onetrust.otpublishers.headless.Public.DataModel.OTConfiguration;
import com.onetrust.otpublishers.headless.Public.Keys.OTFragmentTags;
import com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public class n extends Fragment implements View.OnKeyListener, View.OnFocusChangeListener {
    public com.onetrust.otpublishers.headless.Internal.Event.a A;
    public boolean B;
    public OTConfiguration C;
    public I a;
    public g b;
    public RecyclerView c;
    public com.onetrust.otpublishers.headless.UI.TVUI.datautils.c d;
    public com.onetrust.otpublishers.headless.UI.TVUI.datautils.d e;
    public RelativeLayout f;
    public LinearLayout g;
    public ImageView h;
    public ImageView i;
    public View j;
    public ArrayList k = new ArrayList();
    public com.onetrust.otpublishers.headless.UI.TVUI.adapter.r l;
    public View m;
    public TextView n;
    public l o;
    public Button p;
    public Button q;
    public Button r;
    public Button s;
    public Button t;
    public Button u;
    public Button v;
    public ImageView w;
    public ArrayList x;
    public String y;
    public OTPublishersHeadlessSDK z;

    public final void G(Button button, androidx.constraintlayout.motion.widget.n nVar, boolean z) {
        if (z) {
            button.setElevation(6.0f);
            if (!com.onetrust.otpublishers.headless.Internal.a.j((String) nVar.g)) {
                AbstractC3617f4.h(true, button, this.d, "300", false);
                return;
            } else {
                if (com.onetrust.otpublishers.headless.Internal.a.j((String) nVar.l) || com.onetrust.otpublishers.headless.Internal.a.j((String) nVar.m)) {
                    return;
                }
                button.getBackground().setTint(Color.parseColor((String) nVar.l));
                button.setTextColor(Color.parseColor((String) nVar.m));
                return;
            }
        }
        button.setElevation(DefinitionKt.NO_Float_VALUE);
        if ((this.x.contains("A_F") && button.getText().toString().startsWith("A")) || ((this.x.contains("G_L") && button.getText().toString().startsWith("G")) || ((this.x.contains("M_R") && button.getText().toString().startsWith("M")) || (this.x.contains("S_Z") && button.getText().toString().startsWith("S"))))) {
            if (!com.onetrust.otpublishers.headless.Internal.a.j((String) nVar.g)) {
                AbstractC3617f4.h(false, button, this.d, "300", true);
                return;
            } else {
                button.getBackground().setTint(Color.parseColor((String) this.d.j.B.f));
                button.setTextColor(Color.parseColor((String) this.d.j.B.g));
                return;
            }
        }
        if (!com.onetrust.otpublishers.headless.Internal.a.j((String) nVar.g)) {
            AbstractC3617f4.h(false, button, this.d, "300", false);
        } else {
            button.getBackground().setTint(Color.parseColor((String) nVar.e));
            button.setTextColor(Color.parseColor((String) nVar.f));
        }
    }

    public final void H(Button button, String str) {
        String str2;
        button.setSelected(!button.isSelected());
        if (button.isSelected()) {
            this.y = str;
            this.x.add(str);
            com.onetrust.otpublishers.headless.UI.UIProperty.e eVar = this.d.j;
            c0 c0Var = eVar.B;
            String str3 = (String) c0Var.f;
            String str4 = (String) c0Var.g;
            if (!com.onetrust.otpublishers.headless.Internal.a.j((String) eVar.y.g)) {
                AbstractC3617f4.h(false, button, this.d, "300", true);
            } else if (str3 != null && str4 != null) {
                button.getBackground().setTint(Color.parseColor(str3));
                button.setTextColor(Color.parseColor(str4));
            }
        } else {
            this.x.remove(str);
            com.onetrust.otpublishers.headless.UI.UIProperty.e eVar2 = this.d.j;
            c0 c0Var2 = eVar2.B;
            String str5 = (String) c0Var2.f;
            String str6 = (String) c0Var2.g;
            if (!com.onetrust.otpublishers.headless.Internal.a.j((String) eVar2.y.g)) {
                AbstractC3617f4.h(false, button, this.d, "300", false);
            } else if (str5 != null && str6 != null) {
                button.getBackground().setTint(Color.parseColor(str5));
                button.setTextColor(Color.parseColor(str6));
            }
            if (this.x.size() != 0) {
                str2 = this.x.contains(this.y) ? "A_F" : (String) android.support.v4.media.session.a.e(1, this.x);
            }
            this.y = str2;
        }
        com.onetrust.otpublishers.headless.UI.TVUI.adapter.r rVar = this.l;
        rVar.g = this.x;
        ArrayList arrayListD = rVar.d();
        com.onetrust.otpublishers.headless.UI.TVUI.adapter.r rVar2 = this.l;
        rVar2.e = 0;
        rVar2.notifyDataSetChanged();
        if (arrayListD == null || arrayListD.isEmpty()) {
            return;
        }
        JSONObject jSONObject = (JSONObject) arrayListD.get(0);
        com.onetrust.otpublishers.headless.Internal.Event.a aVar = this.A;
        OTPublishersHeadlessSDK oTPublishersHeadlessSDK = this.z;
        l lVar = new l();
        Bundle bundle = new Bundle();
        bundle.putString(OTFragmentTags.FRAGMENT_TAG, OTFragmentTags.OT_SDK_DETAIL_FRAGMENT);
        lVar.setArguments(bundle);
        lVar.p = this;
        lVar.l = jSONObject;
        lVar.u = aVar;
        lVar.v = oTPublishersHeadlessSDK;
        this.o = lVar;
        I(lVar);
    }

    public final void I(l lVar) {
        AbstractC1136h0 childFragmentManager = getChildFragmentManager();
        childFragmentManager.getClass();
        C1121a c1121a = new C1121a(childFragmentManager);
        c1121a.l(R.id.ot_sdk_detail_container, lVar, null);
        c1121a.d(null);
        c1121a.g();
        lVar.getLifecycle().a(new X0(this, 3));
    }

    public final void a() throws JSONException {
        ArrayList<String> arrayList;
        com.onetrust.otpublishers.headless.Internal.Preferences.f fVar;
        boolean z;
        ArrayList arrayList2 = this.k;
        if (arrayList2 == null || arrayList2.isEmpty()) {
            JSONArray jSONArrayG = P.g((JSONObject) com.onetrust.otpublishers.headless.UI.TVUI.datautils.d.a().a);
            JSONArray jSONArray = new JSONArray();
            for (int i = 0; i < jSONArrayG.length(); i++) {
                try {
                    com.onetrust.otpublishers.headless.UI.TVUI.datautils.d.b(i, jSONArrayG, jSONArray, new JSONObject());
                } catch (JSONException e) {
                    Z.p("Error on parsing Categories list. Error msg = ", e, "TVDataUtils", 6);
                }
            }
            ArrayList arrayList3 = new ArrayList();
            for (int i2 = 0; i2 < jSONArray.length(); i2++) {
                try {
                    arrayList3.add(jSONArray.getJSONObject(i2).optString("CustomGroupId", ""));
                } catch (JSONException e2) {
                    W.a("addCategoriesToMapForClearFilter: ", e2, "TVDataUtils", 6);
                }
            }
            arrayList = arrayList3;
        } else {
            arrayList = this.k;
        }
        Context contextRequireContext = requireContext();
        new JSONObject();
        SharedPreferences sharedPreferences = contextRequireContext.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
        if (Q.a(contextRequireContext)) {
            fVar = new com.onetrust.otpublishers.headless.Internal.Preferences.f(contextRequireContext, sharedPreferences, sharedPreferences.getString("OT_ACTIVE_PROFILE_ID", ""));
            z = true;
        } else {
            fVar = null;
            z = false;
        }
        if (z) {
            sharedPreferences = fVar;
        }
        new com.onetrust.otpublishers.headless.Internal.Preferences.d(contextRequireContext);
        OTPublishersHeadlessSDK oTPublishersHeadlessSDK = this.z;
        if (arrayList == null || arrayList.isEmpty()) {
            return;
        }
        for (String str : arrayList) {
            String string = sharedPreferences.getString("OTT_INTERNAL_SDK_GROUP_MAP", "");
            JSONArray jSONArray2 = new JSONArray();
            if (!com.onetrust.otpublishers.headless.Internal.a.j(string)) {
                try {
                    JSONObject jSONObject = new JSONObject(string);
                    if (jSONObject.has(str)) {
                        jSONArray2 = new JSONArray(jSONObject.get(str).toString());
                    }
                } catch (JSONException e3) {
                    Z.p("Error while fetching Sdks by group : ", e3, "SdkListHelper", 6);
                }
            }
            int purposeConsentLocal = oTPublishersHeadlessSDK.getPurposeConsentLocal(str);
            int length = jSONArray2.length();
            if (length == 1) {
                int consentStatusForSDKId = oTPublishersHeadlessSDK.getConsentStatusForSDKId(jSONArray2.optString(0));
                if (purposeConsentLocal != consentStatusForSDKId) {
                    oTPublishersHeadlessSDK.updatePurposeConsent(str, consentStatusForSDKId == 1, true);
                }
            } else {
                for (int i3 = 1; i3 < length; i3++) {
                    int consentStatusForSDKId2 = oTPublishersHeadlessSDK.getConsentStatusForSDKId(jSONArray2.optString(i3 - 1));
                    int consentStatusForSDKId3 = oTPublishersHeadlessSDK.getConsentStatusForSDKId(jSONArray2.optString(i3));
                    if (consentStatusForSDKId2 != consentStatusForSDKId3) {
                        break;
                    }
                    if (i3 == length - 1) {
                        oTPublishersHeadlessSDK.updatePurposeConsent(str, consentStatusForSDKId3 == 1, true);
                    }
                }
            }
        }
    }

    @Override // androidx.fragment.app.Fragment
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        this.a = getActivity();
        this.d = com.onetrust.otpublishers.headless.UI.TVUI.datautils.c.i();
        this.e = com.onetrust.otpublishers.headless.UI.TVUI.datautils.d.a();
        this.x = new ArrayList();
        this.y = "A_F";
    }

    /* JADX WARN: Removed duplicated region for block: B:59:0x0302  */
    @Override // androidx.fragment.app.Fragment
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final android.view.View onCreateView(android.view.LayoutInflater r18, android.view.ViewGroup r19, android.os.Bundle r20) {
        /*
            Method dump skipped, instructions count: 1002
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.UI.TVUI.fragments.n.onCreateView(android.view.LayoutInflater, android.view.ViewGroup, android.os.Bundle):android.view.View");
    }

    @Override // android.view.View.OnFocusChangeListener
    public final void onFocusChange(View view, boolean z) {
        Drawable drawable;
        String str;
        if (view.getId() == R.id.tv_btn_sdk_confirm) {
            AbstractC3617f4.k(this.p, this.d.j.y, z);
        }
        if (view.getId() == R.id.tv_btn_sdk_reject) {
            AbstractC3617f4.k(this.r, this.d.j.x, z);
        }
        if (view.getId() == R.id.tv_btn_sdk_accept) {
            AbstractC3617f4.k(this.q, this.d.j.w, z);
        }
        if (view.getId() == R.id.ot_tv_alphabet_a_f_sdk) {
            G(this.s, this.d.j.y, z);
        }
        if (view.getId() == R.id.ot_tv_alphabet_g_l_sdk) {
            G(this.t, this.d.j.y, z);
        }
        if (view.getId() == R.id.ot_tv_alphabet_m_r_sdk) {
            G(this.u, this.d.j.y, z);
        }
        if (view.getId() == R.id.ot_tv_alphabet_s_z_sdk) {
            G(this.v, this.d.j.y, z);
        }
        if (view.getId() == R.id.ot_sdk_tv_filter) {
            ImageView imageView = this.w;
            if (z) {
                drawable = imageView.getDrawable();
                str = (String) ((androidx.constraintlayout.motion.widget.n) this.e.g).l;
            } else {
                ArrayList arrayList = this.k;
                if (arrayList == null || arrayList.isEmpty()) {
                    drawable = imageView.getDrawable();
                    str = (String) ((androidx.constraintlayout.motion.widget.n) this.e.g).e;
                } else {
                    drawable = imageView.getDrawable();
                    str = (String) ((androidx.constraintlayout.motion.widget.n) this.e.g).f;
                }
            }
            drawable.setTint(Color.parseColor(str));
        }
        if (view.getId() == R.id.ot_sdk_back_tv) {
            AbstractC3617f4.i(z, this.d.j.y, this.i);
        }
    }

    @Override // android.view.View.OnKeyListener
    public final boolean onKey(View view, int i, KeyEvent keyEvent) throws JSONException {
        if (view.getId() == R.id.ot_sdk_back_tv && AbstractC3617f4.a(i, keyEvent) == 21) {
            a();
            this.b.p(23);
        }
        if (view.getId() == R.id.tv_btn_sdk_confirm && AbstractC3617f4.a(i, keyEvent) == 21) {
            a();
            this.b.p(43);
        }
        if ((view.getId() == R.id.tv_btn_sdk_accept || view.getId() == R.id.tv_btn_sdk_reject || view.getId() == R.id.tv_btn_sdk_confirm) && AbstractC3617f4.a(i, keyEvent) == 25) {
            if (!this.B) {
                this.l.notifyDataSetChanged();
                return true;
            }
            l lVar = this.o;
            if (lVar.g.getVisibility() == 0) {
                lVar.g.requestFocus();
                return true;
            }
            lVar.d.setFocusableInTouchMode(true);
            if (!com.onetrust.otpublishers.headless.Internal.a.j(lVar.d.getText().toString())) {
                lVar.d.requestFocus();
            }
            return true;
        }
        if (view.getId() == R.id.tv_btn_sdk_accept && AbstractC3617f4.a(i, keyEvent) == 21) {
            this.b.p(41);
        }
        if (view.getId() == R.id.tv_btn_sdk_reject && AbstractC3617f4.a(i, keyEvent) == 21) {
            this.b.p(42);
        }
        if (view.getId() == R.id.ot_sdk_tv_filter && AbstractC3617f4.a(i, keyEvent) == 21) {
            ArrayList arrayList = this.k;
            m mVar = new m();
            Bundle bundle = new Bundle();
            bundle.putString("TV_PC_CONTENT", OTFragmentTags.OT_SDK_LIST_FILTER_FRAGMENT_TAG);
            mVar.setArguments(bundle);
            mVar.g = arrayList;
            mVar.c = this;
            AbstractC1136h0 childFragmentManager = getChildFragmentManager();
            childFragmentManager.getClass();
            C1121a c1121a = new C1121a(childFragmentManager);
            c1121a.l(R.id.ot_sdk_detail_container, mVar, null);
            c1121a.d(null);
            c1121a.g();
        }
        if (view.getId() == R.id.ot_tv_alphabet_a_f_sdk && AbstractC3617f4.a(i, keyEvent) == 21) {
            H(this.s, "A_F");
        }
        if (view.getId() == R.id.ot_tv_alphabet_g_l_sdk && AbstractC3617f4.a(i, keyEvent) == 21) {
            H(this.t, "G_L");
        }
        if (view.getId() == R.id.ot_tv_alphabet_m_r_sdk && AbstractC3617f4.a(i, keyEvent) == 21) {
            H(this.u, "M_R");
        }
        if (view.getId() != R.id.ot_tv_alphabet_s_z_sdk || AbstractC3617f4.a(i, keyEvent) != 21) {
            return false;
        }
        H(this.v, "S_Z");
        return false;
    }
}

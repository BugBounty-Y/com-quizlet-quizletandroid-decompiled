package com.onetrust.otpublishers.headless.UI.TVUI.fragments;

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
import androidx.fragment.app.AbstractC1136h0;
import androidx.fragment.app.C1121a;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.I;
import androidx.lifecycle.C;
import androidx.recyclerview.widget.RecyclerView;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3617f4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.W;
import com.onetrust.otpublishers.headless.Public.DataModel.OTConfiguration;
import com.onetrust.otpublishers.headless.Public.Keys.OTFragmentTags;
import com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK;
import com.onetrust.otpublishers.headless.Public.OTVendorListMode;
import com.onetrust.otpublishers.headless.Public.uiutils.OTVendorUtils;
import com.onetrust.otpublishers.headless.UI.TVUI.adapter.B;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Objects;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public class s extends Fragment implements View.OnKeyListener, OTVendorUtils.ItemListener, View.OnFocusChangeListener {
    public Button A;
    public Button B;
    public Button C;
    public Button D;
    public ImageView E;
    public ArrayList F;
    public String G;
    public boolean I;
    public OTConfiguration J;
    public I a;
    public OTPublishersHeadlessSDK b;
    public g c;
    public com.onetrust.otpublishers.headless.Internal.Event.a d;
    public RecyclerView e;
    public com.onetrust.otpublishers.headless.UI.TVUI.datautils.c f;
    public com.onetrust.otpublishers.headless.UI.TVUI.datautils.d g;
    public RelativeLayout h;
    public LinearLayout i;
    public ImageView j;
    public ImageView k;
    public View l;
    public boolean n;
    public OTVendorUtils o;
    public B p;
    public com.onetrust.otpublishers.headless.UI.TVUI.adapter.c q;
    public View r;
    public TextView s;
    public p t;
    public b u;
    public Button v;
    public Button w;
    public Button x;
    public Button y;
    public Button z;
    public HashMap m = new HashMap();
    public String H = OTVendorListMode.IAB;

    public static void J(Button button, String str, String str2) {
        if (str == null || str2 == null) {
            return;
        }
        button.getBackground().setTint(Color.parseColor(str));
        button.setTextColor(Color.parseColor(str2));
    }

    public final void G(Button button, androidx.constraintlayout.motion.widget.n nVar, String str, boolean z) {
        if (z) {
            if (!com.onetrust.otpublishers.headless.Internal.a.j((String) nVar.g)) {
                AbstractC3617f4.h(false, button, this.f, str, true);
                return;
            } else {
                button.getBackground().setTint(Color.parseColor((String) this.f.j.B.f));
                button.setTextColor(Color.parseColor((String) this.f.j.B.g));
                return;
            }
        }
        if (!com.onetrust.otpublishers.headless.Internal.a.j((String) nVar.g)) {
            AbstractC3617f4.h(false, button, this.f, str, false);
        } else {
            button.getBackground().setTint(Color.parseColor((String) nVar.e));
            button.setTextColor(Color.parseColor((String) nVar.f));
        }
    }

    public final void H(Button button, androidx.constraintlayout.motion.widget.n nVar, boolean z) {
        boolean z2 = false;
        if (z) {
            button.setElevation(6.0f);
            if (!com.onetrust.otpublishers.headless.Internal.a.j((String) nVar.g)) {
                AbstractC3617f4.h(true, button, this.f, "300", false);
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
        if ((this.F.contains("A_F") && button.getText().toString().startsWith("A")) || ((this.F.contains("G_L") && button.getText().toString().startsWith("G")) || ((this.F.contains("M_R") && button.getText().toString().startsWith("M")) || (this.F.contains("S_Z") && button.getText().toString().startsWith("S"))))) {
            z2 = true;
        }
        G(button, nVar, "300", z2);
    }

    public final void I(Button button, String str) {
        String str2;
        button.setSelected(!button.isSelected());
        if (button.isSelected()) {
            this.G = str;
            this.F.add(str);
            com.onetrust.otpublishers.headless.UI.UIProperty.e eVar = this.f.j;
            c0 c0Var = eVar.B;
            String str3 = (String) c0Var.f;
            String str4 = (String) c0Var.g;
            if (com.onetrust.otpublishers.headless.Internal.a.j((String) eVar.y.g)) {
                J(button, str3, str4);
            } else {
                AbstractC3617f4.h(false, button, this.f, "300", true);
            }
        } else {
            this.F.remove(str);
            androidx.constraintlayout.motion.widget.n nVar = this.f.j.y;
            String str5 = (String) nVar.e;
            String str6 = (String) nVar.f;
            if (com.onetrust.otpublishers.headless.Internal.a.j((String) nVar.g)) {
                J(button, str5, str6);
            } else {
                AbstractC3617f4.h(false, button, this.f, "300", false);
            }
            if (!this.F.isEmpty()) {
                str2 = this.F.contains(this.G) ? "A_F" : (String) android.support.v4.media.session.a.e(1, this.F);
            }
            this.G = str2;
        }
        if (OTVendorListMode.IAB.equalsIgnoreCase(this.H)) {
            B b = this.p;
            b.j = this.F;
            b.g();
            B b2 = this.p;
            b2.g = 0;
            b2.notifyDataSetChanged();
            return;
        }
        if (OTVendorListMode.GOOGLE.equalsIgnoreCase(this.H)) {
            com.onetrust.otpublishers.headless.UI.TVUI.adapter.c cVar = this.q;
            cVar.h = this.F;
            cVar.g();
            com.onetrust.otpublishers.headless.UI.TVUI.adapter.c cVar2 = this.q;
            cVar2.e = 0;
            cVar2.notifyDataSetChanged();
        }
    }

    public final void K(Fragment fragment) {
        AbstractC1136h0 childFragmentManager = getChildFragmentManager();
        childFragmentManager.getClass();
        C1121a c1121a = new C1121a(childFragmentManager);
        c1121a.l(R.id.ot_vl_detail_container, fragment, null);
        c1121a.d(null);
        c1121a.g();
        fragment.getLifecycle().a(new r(this, 0));
    }

    public final void L(String str) {
        if (com.onetrust.otpublishers.headless.Internal.a.j(str)) {
            return;
        }
        if (OTVendorListMode.IAB.equalsIgnoreCase(this.H)) {
            if (this.b.getVendorDetails(OTVendorListMode.IAB, str) == null) {
                this.b.reInitVendorArray();
            }
            com.onetrust.otpublishers.headless.Internal.Event.a aVar = this.d;
            OTPublishersHeadlessSDK oTPublishersHeadlessSDK = this.b;
            p pVar = new p();
            Bundle bundle = new Bundle();
            bundle.putString(OTFragmentTags.FRAGMENT_TAG, OTFragmentTags.OT_VENDOR_DETAILS_FRAGMENT_TAG);
            pVar.setArguments(bundle);
            pVar.s = this;
            pVar.q = oTPublishersHeadlessSDK;
            pVar.r = oTPublishersHeadlessSDK.getVendorDetails(Integer.parseInt(str));
            pVar.y = aVar;
            this.t = pVar;
            K(pVar);
            return;
        }
        if (OTVendorListMode.GOOGLE.equalsIgnoreCase(this.H)) {
            if (this.b.getVendorDetails(OTVendorListMode.GOOGLE, str) == null) {
                this.b.reInitVendorArray();
            }
            com.onetrust.otpublishers.headless.Internal.Event.a aVar2 = this.d;
            OTPublishersHeadlessSDK oTPublishersHeadlessSDK2 = this.b;
            b bVar = new b();
            Bundle bundle2 = new Bundle();
            bundle2.putString(OTFragmentTags.FRAGMENT_TAG, OTFragmentTags.OT_VENDOR_DETAILS_FRAGMENT_TAG);
            bVar.setArguments(bundle2);
            bVar.k = this;
            bVar.i = oTPublishersHeadlessSDK2;
            bVar.j = oTPublishersHeadlessSDK2.getVendorDetails(OTVendorListMode.GOOGLE, str);
            bVar.n = aVar2;
            this.u = bVar;
            K(bVar);
        }
    }

    public final void M(String str, String str2) {
        if (com.onetrust.otpublishers.headless.Internal.a.j((String) this.f.j.y.g)) {
            J(this.y, str, str2);
            J(this.z, str, str2);
            J(this.A, str, str2);
            J(this.B, str, str2);
            J(this.C, str, str2);
            J(this.D, str, str2);
            this.C.setMinHeight(70);
            this.C.setMinimumHeight(70);
            this.D.setMinHeight(70);
            this.D.setMinimumHeight(70);
            return;
        }
        AbstractC3617f4.h(false, this.y, this.f, "300", false);
        AbstractC3617f4.h(false, this.z, this.f, "300", false);
        AbstractC3617f4.h(false, this.A, this.f, "300", false);
        AbstractC3617f4.h(false, this.B, this.f, "300", false);
        AbstractC3617f4.h(false, this.C, this.f, "3", false);
        AbstractC3617f4.h(false, this.D, this.f, "3", false);
        this.C.setMinHeight(0);
        this.C.setMinimumHeight(0);
        this.D.setMinHeight(0);
        this.D.setMinimumHeight(0);
        this.C.setPadding(0, 5, 0, 5);
        this.D.setPadding(0, 5, 0, 5);
    }

    public final void N() {
        C lifecycle;
        r rVar;
        this.I = true;
        if (!OTVendorListMode.IAB.equalsIgnoreCase(this.H)) {
            if (OTVendorListMode.GOOGLE.equalsIgnoreCase(this.H)) {
                lifecycle = this.u.getLifecycle();
                rVar = new r(this, 2);
            }
            this.x.clearFocus();
            this.w.clearFocus();
            this.v.clearFocus();
        }
        lifecycle = this.t.getLifecycle();
        rVar = new r(this, 1);
        lifecycle.a(rVar);
        this.x.clearFocus();
        this.w.clearFocus();
        this.v.clearFocus();
    }

    public final void O(Button button, androidx.constraintlayout.motion.widget.n nVar, boolean z) {
        if (!z) {
            button.setElevation(DefinitionKt.NO_Float_VALUE);
            G(button, nVar, "3", button.isSelected());
            return;
        }
        button.setElevation(6.0f);
        if (!com.onetrust.otpublishers.headless.Internal.a.j((String) nVar.g)) {
            AbstractC3617f4.m(button, nVar, true);
        } else {
            if (com.onetrust.otpublishers.headless.Internal.a.j((String) nVar.l) || com.onetrust.otpublishers.headless.Internal.a.j((String) nVar.m)) {
                return;
            }
            button.getBackground().setTint(Color.parseColor((String) nVar.l));
            button.setTextColor(Color.parseColor((String) nVar.m));
        }
    }

    public final void P() {
        com.onetrust.otpublishers.headless.UI.TVUI.adapter.c cVar = new com.onetrust.otpublishers.headless.UI.TVUI.adapter.c(this.o, this, this.b);
        this.q = cVar;
        cVar.g();
        this.e.setAdapter(this.q);
        this.E.setVisibility(4);
        this.s.setText(this.f.l);
        this.C.setSelected(false);
        this.D.setSelected(true);
        O(this.D, this.f.j.y, false);
        JSONObject vendorListUI = this.b.getVendorListUI(OTVendorListMode.GOOGLE);
        if (vendorListUI == null || vendorListUI.length() <= 0) {
            return;
        }
        JSONArray jSONArrayNames = vendorListUI.names();
        Objects.requireNonNull(jSONArrayNames);
        L(jSONArrayNames.getString(0));
    }

    public final void Q() {
        B b = new B(this.o, this, this.b, this.n, this.m);
        this.p = b;
        b.g();
        this.e.setAdapter(this.p);
        if (8 == ((androidx.constraintlayout.motion.widget.n) this.g.g).b) {
            this.E.setVisibility(4);
        } else {
            this.E.setVisibility(0);
        }
        this.s.setText(this.f.k);
        this.C.setSelected(true);
        this.D.setSelected(false);
        O(this.C, this.f.j.y, false);
        JSONObject vendorsByPurpose = this.n ? this.o.getVendorsByPurpose(this.m, this.b.getVendorListUI(OTVendorListMode.IAB)) : this.b.getVendorListUI(OTVendorListMode.IAB);
        if (vendorsByPurpose == null || vendorsByPurpose.length() <= 0) {
            return;
        }
        JSONArray jSONArrayNames = vendorsByPurpose.names();
        Objects.requireNonNull(jSONArrayNames);
        L(jSONArrayNames.getString(0));
    }

    public final void a() {
        this.F.clear();
        this.B.setSelected(false);
        this.z.setSelected(false);
        this.A.setSelected(false);
        this.y.setSelected(false);
        androidx.constraintlayout.motion.widget.n nVar = this.f.j.y;
        J(this.y, (String) nVar.e, (String) nVar.f);
        J(this.z, (String) nVar.e, (String) nVar.f);
        J(this.A, (String) nVar.e, (String) nVar.f);
        J(this.B, (String) nVar.e, (String) nVar.f);
    }

    @Override // androidx.fragment.app.Fragment
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        this.a = getActivity();
        this.f = com.onetrust.otpublishers.headless.UI.TVUI.datautils.c.i();
        this.g = com.onetrust.otpublishers.headless.UI.TVUI.datautils.d.a();
        this.F = new ArrayList();
        this.G = "A_F";
    }

    /* JADX WARN: Removed duplicated region for block: B:40:0x02a1  */
    @Override // androidx.fragment.app.Fragment
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final android.view.View onCreateView(android.view.LayoutInflater r18, android.view.ViewGroup r19, android.os.Bundle r20) {
        /*
            Method dump skipped, instructions count: 959
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.UI.TVUI.fragments.s.onCreateView(android.view.LayoutInflater, android.view.ViewGroup, android.os.Bundle):android.view.View");
    }

    @Override // android.view.View.OnFocusChangeListener
    public final void onFocusChange(View view, boolean z) {
        Drawable drawable;
        String str;
        if (view.getId() == R.id.tv_btn_vl_confirm) {
            AbstractC3617f4.k(this.v, this.f.j.y, z);
        }
        if (view.getId() == R.id.tv_btn_vl_reject) {
            AbstractC3617f4.k(this.x, this.f.j.x, z);
        }
        if (view.getId() == R.id.tv_btn_vl_accept) {
            AbstractC3617f4.k(this.w, this.f.j.w, z);
        }
        if (view.getId() == R.id.ot_tv_alphabet_a_f) {
            H(this.y, this.f.j.y, z);
        }
        if (view.getId() == R.id.ot_tv_alphabet_g_l) {
            H(this.z, this.f.j.y, z);
        }
        if (view.getId() == R.id.ot_tv_alphabet_m_r) {
            H(this.A, this.f.j.y, z);
        }
        if (view.getId() == R.id.ot_tv_alphabet_s_z) {
            H(this.B, this.f.j.y, z);
        }
        if (view.getId() == R.id.tv_google_tab) {
            O(this.D, this.f.j.y, z);
        }
        if (view.getId() == R.id.tv_iab_tab) {
            O(this.C, this.f.j.y, z);
        }
        if (view.getId() == R.id.ot_vl_tv_filter) {
            ImageView imageView = this.E;
            if (z) {
                drawable = imageView.getDrawable();
                str = (String) ((androidx.constraintlayout.motion.widget.n) this.g.g).l;
            } else {
                HashMap map = this.m;
                if (map == null || map.isEmpty()) {
                    drawable = imageView.getDrawable();
                    str = (String) ((androidx.constraintlayout.motion.widget.n) this.g.g).e;
                } else {
                    drawable = imageView.getDrawable();
                    str = (String) ((androidx.constraintlayout.motion.widget.n) this.g.g).f;
                }
            }
            drawable.setTint(Color.parseColor(str));
        }
        if (view.getId() == R.id.ot_vl_back) {
            AbstractC3617f4.i(z, this.f.j.y, this.k);
        }
    }

    @Override // com.onetrust.otpublishers.headless.Public.uiutils.OTVendorUtils.ItemListener
    public final void onItemClick(String str, boolean z) {
    }

    @Override // android.view.View.OnKeyListener
    public final boolean onKey(View view, int i, KeyEvent keyEvent) {
        com.onetrust.otpublishers.headless.UI.TVUI.adapter.c cVar;
        b bVar;
        View view2;
        p pVar;
        if (view.getId() == R.id.ot_vl_back && AbstractC3617f4.a(i, keyEvent) == 21) {
            this.c.p(23);
        }
        if (view.getId() == R.id.tv_btn_vl_confirm && AbstractC3617f4.a(i, keyEvent) == 21) {
            this.c.p(33);
        }
        if ((view.getId() == R.id.tv_btn_vl_accept || view.getId() == R.id.tv_btn_vl_reject || view.getId() == R.id.tv_btn_vl_confirm) && AbstractC3617f4.a(i, keyEvent) == 25) {
            if (!this.I) {
                if (OTVendorListMode.IAB.equalsIgnoreCase(this.H)) {
                    this.p.notifyDataSetChanged();
                }
                if (!OTVendorListMode.GOOGLE.equalsIgnoreCase(this.H) || (cVar = this.q) == null) {
                    return true;
                }
                cVar.notifyDataSetChanged();
                return true;
            }
            if (OTVendorListMode.IAB.equalsIgnoreCase(this.H) && (pVar = this.t) != null) {
                pVar.L();
            }
            if (!OTVendorListMode.GOOGLE.equalsIgnoreCase(this.H) || (bVar = this.u) == null) {
                return true;
            }
            TextView textView = bVar.b;
            if (textView == null || com.onetrust.otpublishers.headless.Internal.a.j(textView.getText().toString())) {
                view2 = bVar.e;
                if (view2 == null) {
                    return true;
                }
            } else {
                view2 = bVar.b;
            }
            view2.requestFocus();
            return true;
        }
        if (view.getId() == R.id.tv_btn_vl_accept && AbstractC3617f4.a(i, keyEvent) == 21) {
            this.c.p(31);
        }
        if (view.getId() == R.id.tv_btn_vl_reject && AbstractC3617f4.a(i, keyEvent) == 21) {
            this.c.p(32);
        }
        if (view.getId() == R.id.ot_vl_tv_filter && AbstractC3617f4.a(i, keyEvent) == 21) {
            HashMap map = this.m;
            q qVar = new q();
            Bundle bundle = new Bundle();
            bundle.putString("TV_PC_CONTENT", OTFragmentTags.OT_VENDOR_LIST_FILTER_FRAGMENT_TAG);
            qVar.setArguments(bundle);
            qVar.c = this;
            qVar.g = map;
            AbstractC1136h0 childFragmentManager = getChildFragmentManager();
            childFragmentManager.getClass();
            C1121a c1121a = new C1121a(childFragmentManager);
            c1121a.l(R.id.ot_vl_detail_container, qVar, null);
            c1121a.d(null);
            c1121a.g();
        }
        if (view.getId() == R.id.ot_tv_alphabet_a_f && AbstractC3617f4.a(i, keyEvent) == 21) {
            I(this.y, "A_F");
        }
        if (view.getId() == R.id.ot_tv_alphabet_g_l && AbstractC3617f4.a(i, keyEvent) == 21) {
            I(this.z, "G_L");
        }
        if (view.getId() == R.id.ot_tv_alphabet_m_r && AbstractC3617f4.a(i, keyEvent) == 21) {
            I(this.A, "M_R");
        }
        if (view.getId() == R.id.ot_tv_alphabet_s_z && AbstractC3617f4.a(i, keyEvent) == 21) {
            I(this.B, "S_Z");
        }
        if (view.getId() == R.id.tv_iab_tab && AbstractC3617f4.a(i, keyEvent) == 21) {
            try {
                this.H = OTVendorListMode.IAB;
                a();
                Q();
                O(this.D, this.f.j.y, false);
                androidx.constraintlayout.motion.widget.n nVar = this.f.j.y;
                M((String) nVar.e, (String) nVar.f);
            } catch (JSONException e) {
                W.a("onKey: error on setIABVendorData , ", e, "TVVendorList", 6);
            }
        }
        if (view.getId() == R.id.tv_google_tab && AbstractC3617f4.a(i, keyEvent) == 21) {
            try {
                this.H = OTVendorListMode.GOOGLE;
                a();
                P();
                O(this.C, this.f.j.y, false);
                androidx.constraintlayout.motion.widget.n nVar2 = this.f.j.y;
                M((String) nVar2.e, (String) nVar2.f);
            } catch (JSONException e2) {
                W.a("onKey: error on setGoogleVendorData , ", e2, "TVVendorList", 6);
            }
        }
        return false;
    }

    public final void p(int i) {
        com.onetrust.otpublishers.headless.UI.TVUI.adapter.c cVar;
        B b;
        if (i != 24) {
            getChildFragmentManager().W();
            return;
        }
        if (OTVendorListMode.IAB.equalsIgnoreCase(this.H) && (b = this.p) != null) {
            b.notifyDataSetChanged();
        }
        if (!OTVendorListMode.GOOGLE.equalsIgnoreCase(this.H) || (cVar = this.q) == null) {
            return;
        }
        cVar.notifyDataSetChanged();
    }
}

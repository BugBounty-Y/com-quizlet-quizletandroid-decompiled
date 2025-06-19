package com.onetrust.otpublishers.headless.UI.TVUI.fragments;

import android.graphics.Color;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.view.KeyEvent;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.TextView;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.I;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3617f4;
import com.google.android.gms.measurement.internal.Z;
import com.onetrust.otpublishers.headless.Public.OTVendorListMode;
import com.onetrust.otpublishers.headless.UI.TVUI.adapter.B;
import com.quizlet.quizletandroid.R;
import java.util.HashMap;
import java.util.Objects;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public class q extends Fragment implements View.OnKeyListener, View.OnFocusChangeListener {
    public TextView a;
    public I b;
    public s c;
    public RecyclerView d;
    public com.onetrust.otpublishers.headless.UI.TVUI.datautils.c e;
    public com.onetrust.otpublishers.headless.UI.TVUI.datautils.d f;
    public HashMap g = new HashMap();
    public Button h;
    public Button i;
    public com.onetrust.otpublishers.headless.UI.TVUI.adapter.p j;

    @Override // androidx.fragment.app.Fragment
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        this.b = getActivity();
        this.e = com.onetrust.otpublishers.headless.UI.TVUI.datautils.c.i();
        this.f = com.onetrust.otpublishers.headless.UI.TVUI.datautils.d.a();
    }

    @Override // androidx.fragment.app.Fragment
    public final View onCreateView(LayoutInflater layoutInflater, ViewGroup viewGroup, Bundle bundle) {
        I i = this.b;
        if (com.onetrust.otpublishers.headless.Internal.a.o(i)) {
            layoutInflater = layoutInflater.cloneInContext(new androidx.appcompat.view.d(i, R.style.Theme_AppCompat_Light_NoActionBar));
        }
        View viewInflate = layoutInflater.inflate(R.layout.ot_tv_purpose_filter, viewGroup, false);
        this.a = (TextView) viewInflate.findViewById(R.id.ot_tv_filter_title);
        this.d = (RecyclerView) viewInflate.findViewById(R.id.ot_tv_filter_list);
        this.i = (Button) viewInflate.findViewById(R.id.ot_tv_filter_clear);
        this.h = (Button) viewInflate.findViewById(R.id.ot_tv_filter_apply);
        this.a.requestFocus();
        this.h.setOnKeyListener(this);
        this.i.setOnKeyListener(this);
        this.h.setOnFocusChangeListener(this);
        this.i.setOnFocusChangeListener(this);
        String strL = this.e.l();
        AbstractC3617f4.k(this.h, this.e.j.y, false);
        AbstractC3617f4.k(this.i, this.e.j.y, false);
        this.a.setTextColor(Color.parseColor(strL));
        try {
            this.i.setText((String) this.f.d);
            this.h.setText((String) this.f.c);
            JSONObject jSONObjectK = this.e.k(this.b);
            if (this.g == null) {
                this.g = new HashMap();
            }
            if (jSONObjectK != null) {
                JSONArray jSONArrayOptJSONArray = jSONObjectK.optJSONArray("Groups");
                if (jSONArrayOptJSONArray == null) {
                    jSONArrayOptJSONArray = new JSONArray();
                }
                this.j = new com.onetrust.otpublishers.headless.UI.TVUI.adapter.p(assistantMode.utils.studiableMetadata.b.p(jSONArrayOptJSONArray), this.e.l(), this.g, this);
                this.d.setLayoutManager(new LinearLayoutManager(this.b));
                this.d.setAdapter(this.j);
                return viewInflate;
            }
        } catch (Exception e) {
            Z.n("error while populating VL fields", e, "TVVendorListFilter", 6);
        }
        return viewInflate;
    }

    @Override // android.view.View.OnFocusChangeListener
    public final void onFocusChange(View view, boolean z) {
        if (view.getId() == R.id.ot_tv_filter_clear) {
            AbstractC3617f4.k(this.i, this.e.j.y, z);
        }
        if (view.getId() == R.id.ot_tv_filter_apply) {
            AbstractC3617f4.k(this.h, this.e.j.y, z);
        }
    }

    @Override // android.view.View.OnKeyListener
    public final boolean onKey(View view, int i, KeyEvent keyEvent) {
        Drawable drawable;
        String str;
        if (view.getId() == R.id.ot_tv_filter_clear && AbstractC3617f4.a(i, keyEvent) == 21) {
            com.onetrust.otpublishers.headless.UI.TVUI.adapter.p pVar = this.j;
            HashMap map = new HashMap();
            pVar.getClass();
            pVar.e = new HashMap(map);
            this.j.notifyDataSetChanged();
            this.g = new HashMap();
        }
        if (view.getId() == R.id.ot_tv_filter_apply && AbstractC3617f4.a(i, keyEvent) == 21) {
            s sVar = this.c;
            HashMap map2 = this.g;
            sVar.getClass();
            sVar.n = !map2.isEmpty();
            sVar.m = map2;
            androidx.constraintlayout.motion.widget.n nVar = (androidx.constraintlayout.motion.widget.n) sVar.g.g;
            if (map2.isEmpty()) {
                drawable = sVar.E.getDrawable();
                str = (String) nVar.e;
            } else {
                drawable = sVar.E.getDrawable();
                str = (String) nVar.f;
            }
            drawable.setTint(Color.parseColor(str));
            sVar.p.e = !map2.isEmpty();
            B b = sVar.p;
            b.f = map2;
            b.g();
            B b2 = sVar.p;
            b2.g = 0;
            b2.notifyDataSetChanged();
            try {
                JSONObject vendorsByPurpose = sVar.n ? sVar.o.getVendorsByPurpose(sVar.m, sVar.b.getVendorListUI(OTVendorListMode.IAB)) : sVar.b.getVendorListUI(OTVendorListMode.IAB);
                if (vendorsByPurpose != null && vendorsByPurpose.length() > 0) {
                    JSONArray jSONArrayNames = vendorsByPurpose.names();
                    Objects.requireNonNull(jSONArrayNames);
                    sVar.L(jSONArrayNames.getString(0));
                }
            } catch (JSONException e) {
                Z.o("error while setting first vendor detail,err ", e, "TVVendorList");
            }
        }
        if (i == 4 && keyEvent.getAction() == 1) {
            this.c.p(23);
        }
        return false;
    }
}

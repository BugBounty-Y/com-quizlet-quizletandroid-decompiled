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
import com.google.android.gms.internal.mlkit_vision_document_scanner.P;
import com.google.android.gms.measurement.internal.Z;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.onetrust.otpublishers.headless.Public.Keys.OTFragmentTags;
import com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK;
import com.quizlet.quizletandroid.R;
import java.util.ArrayList;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public class m extends Fragment implements View.OnKeyListener, View.OnFocusChangeListener {
    public TextView a;
    public I b;
    public n c;
    public RecyclerView d;
    public com.onetrust.otpublishers.headless.UI.TVUI.datautils.c e;
    public com.onetrust.otpublishers.headless.UI.TVUI.datautils.d f;
    public ArrayList g = new ArrayList();
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
        this.a.setText("Filter SDK List");
        this.a.setTextColor(Color.parseColor(strL));
        try {
            this.i.setText((String) this.f.d);
            this.h.setText((String) this.f.c);
            if (this.g == null) {
                this.g = new ArrayList();
            }
            JSONArray jSONArrayG = P.g((JSONObject) this.f.a);
            JSONArray jSONArray = new JSONArray();
            for (int i2 = 0; i2 < jSONArrayG.length(); i2++) {
                try {
                    com.onetrust.otpublishers.headless.UI.TVUI.datautils.d.b(i2, jSONArrayG, jSONArray, new JSONObject());
                } catch (JSONException e) {
                    OTLogger.c("TVDataUtils", 6, "Error on parsing Categories list. Error msg = " + e.getMessage());
                }
            }
            this.j = new com.onetrust.otpublishers.headless.UI.TVUI.adapter.p(jSONArray, this.e.l(), this.g, this);
            this.d.setLayoutManager(new LinearLayoutManager(this.b));
            this.d.setAdapter(this.j);
        } catch (Exception e2) {
            Z.n("error while populating SDK List fields", e2, "TVVendorListFilter", 6);
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
            this.j.e = new ArrayList();
            this.j.notifyDataSetChanged();
            this.g = new ArrayList();
        }
        if (view.getId() == R.id.ot_tv_filter_apply && AbstractC3617f4.a(i, keyEvent) == 21) {
            n nVar = this.c;
            ArrayList arrayList = this.g;
            nVar.k = arrayList;
            androidx.constraintlayout.motion.widget.n nVar2 = (androidx.constraintlayout.motion.widget.n) nVar.e.g;
            if (arrayList.isEmpty()) {
                drawable = nVar.w.getDrawable();
                str = (String) nVar2.e;
            } else {
                drawable = nVar.w.getDrawable();
                str = (String) nVar2.f;
            }
            drawable.setTint(Color.parseColor(str));
            com.onetrust.otpublishers.headless.UI.TVUI.adapter.r rVar = nVar.l;
            rVar.d = arrayList;
            ArrayList arrayListD = rVar.d();
            com.onetrust.otpublishers.headless.UI.TVUI.adapter.r rVar2 = nVar.l;
            rVar2.e = 0;
            rVar2.notifyDataSetChanged();
            if (arrayListD != null && !arrayListD.isEmpty()) {
                JSONObject jSONObject = (JSONObject) arrayListD.get(0);
                com.onetrust.otpublishers.headless.Internal.Event.a aVar = nVar.A;
                OTPublishersHeadlessSDK oTPublishersHeadlessSDK = nVar.z;
                l lVar = new l();
                Bundle bundle = new Bundle();
                bundle.putString(OTFragmentTags.FRAGMENT_TAG, OTFragmentTags.OT_SDK_DETAIL_FRAGMENT);
                lVar.setArguments(bundle);
                lVar.p = nVar;
                lVar.l = jSONObject;
                lVar.u = aVar;
                lVar.v = oTPublishersHeadlessSDK;
                nVar.o = lVar;
                nVar.I(lVar);
            }
        }
        if (i == 4 && keyEvent.getAction() == 1) {
            this.c.getChildFragmentManager().W();
        }
        return false;
    }
}

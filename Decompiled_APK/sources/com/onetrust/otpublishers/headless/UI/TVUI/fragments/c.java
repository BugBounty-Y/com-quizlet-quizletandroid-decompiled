package com.onetrust.otpublishers.headless.UI.TVUI.fragments;

import android.content.Context;
import android.graphics.Color;
import android.os.Bundle;
import android.view.KeyEvent;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.I;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3617f4;
import com.google.android.gms.measurement.internal.Z;
import com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK;
import com.quizlet.quizletandroid.R;
import java.util.ArrayList;
import java.util.HashMap;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public class c extends Fragment implements com.onetrust.otpublishers.headless.UI.TVUI.adapter.j, View.OnKeyListener, View.OnFocusChangeListener {
    public TextView a;
    public TextView b;
    public RecyclerView c;
    public Context d;
    public OTPublishersHeadlessSDK e;
    public JSONObject f;
    public LinearLayout g;
    public k h;
    public com.onetrust.otpublishers.headless.UI.TVUI.datautils.c i;
    public ImageView j;

    public final void G() throws JSONException {
        JSONArray jSONArray;
        com.onetrust.otpublishers.headless.UI.TVUI.datautils.c cVarI = com.onetrust.otpublishers.headless.UI.TVUI.datautils.c.i();
        this.i = cVarI;
        assistantMode.utils.studiableMetadata.b.r(this.d, this.a, cVarI.q);
        Context context = this.d;
        TextView textView = this.b;
        JSONObject jSONObject = this.f;
        assistantMode.utils.studiableMetadata.b.r(context, textView, jSONObject.optString(com.onetrust.otpublishers.headless.Internal.a.j(jSONObject.optString("GroupNameOTT")) ? "GroupName" : "GroupNameOTT"));
        this.j.setVisibility(0);
        com.onetrust.otpublishers.headless.UI.TVUI.datautils.c cVar = this.i;
        String strL = cVar.l();
        com.onetrust.otpublishers.headless.UI.UIProperty.e eVar = cVar.j;
        androidx.navigation.internal.m mVar = eVar.k;
        androidx.navigation.internal.m mVar2 = eVar.s;
        if (!com.onetrust.otpublishers.headless.Internal.a.j((String) ((com.google.android.gms.cloudmessaging.k) mVar.d).d)) {
            this.a.setTextSize(Float.parseFloat((String) ((com.google.android.gms.cloudmessaging.k) mVar.d).d));
        }
        if (!com.onetrust.otpublishers.headless.Internal.a.j((String) ((com.google.android.gms.cloudmessaging.k) mVar2.d).d)) {
            this.b.setTextSize(Float.parseFloat((String) ((com.google.android.gms.cloudmessaging.k) mVar2.d).d));
        }
        if (com.onetrust.otpublishers.headless.Internal.a.j((String) mVar.b)) {
            this.a.setTextColor(Color.parseColor(strL));
        } else {
            this.a.setTextColor(Color.parseColor((String) mVar.b));
        }
        if (com.onetrust.otpublishers.headless.Internal.a.j((String) mVar2.b)) {
            this.b.setTextColor(Color.parseColor(strL));
        } else {
            this.b.setTextColor(Color.parseColor((String) mVar2.b));
        }
        this.g.setBackgroundColor(Color.parseColor(cVar.a()));
        AbstractC3617f4.i(false, cVar.j.y, this.j);
        this.j.setNextFocusDownId(R.id.tv_category_desc);
        if (this.f.has("IabIllustrations")) {
            try {
                jSONArray = this.f.getJSONArray("IabIllustrations");
            } catch (JSONException e) {
                Z.p("Error on parsing iab illustrations. Error = ", e, "TVIllustration", 6);
            }
        } else {
            jSONArray = null;
        }
        if (jSONArray == null || retrofit2.adapter.rxjava3.d.l(jSONArray)) {
            return;
        }
        String strL2 = this.i.l();
        this.b.setTextColor(Color.parseColor(strL2));
        this.c.setAdapter(new com.onetrust.otpublishers.headless.UI.TVUI.adapter.e(this.d, jSONArray, strL2));
    }

    @Override // com.onetrust.otpublishers.headless.UI.TVUI.adapter.j
    public final void a() {
    }

    @Override // androidx.fragment.app.Fragment
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        this.d = getContext();
    }

    @Override // androidx.fragment.app.Fragment
    public final View onCreateView(LayoutInflater layoutInflater, ViewGroup viewGroup, Bundle bundle) throws JSONException {
        Context context = this.d;
        if (com.onetrust.otpublishers.headless.Internal.a.o(context)) {
            layoutInflater = layoutInflater.cloneInContext(new androidx.appcompat.view.d(context, R.style.Theme_AppCompat_Light_NoActionBar));
        }
        View viewInflate = layoutInflater.inflate(R.layout.ot_pc_illustration_detail_tv, viewGroup, false);
        this.a = (TextView) viewInflate.findViewById(R.id.tv_category_title);
        this.b = (TextView) viewInflate.findViewById(R.id.subgroup_list_title);
        this.c = (RecyclerView) viewInflate.findViewById(R.id.tv_subgroup_list);
        this.g = (LinearLayout) viewInflate.findViewById(R.id.tv_grp_detail_lyt);
        this.j = (ImageView) viewInflate.findViewById(R.id.tv_sub_grp_back);
        this.c.setHasFixedSize(true);
        this.c.setLayoutManager(new LinearLayoutManager(getActivity()));
        this.j.setOnKeyListener(this);
        this.j.setOnFocusChangeListener(this);
        G();
        return viewInflate;
    }

    @Override // android.view.View.OnFocusChangeListener
    public final void onFocusChange(View view, boolean z) {
        if (view.getId() == R.id.tv_sub_grp_back) {
            AbstractC3617f4.i(z, this.i.j.y, this.j);
        }
    }

    @Override // android.view.View.OnKeyListener
    public final boolean onKey(View view, int i, KeyEvent keyEvent) {
        Button button;
        if (view.getId() == R.id.card_list_of_partners && AbstractC3617f4.a(i, keyEvent) == 21) {
            HashMap map = new HashMap();
            map.put(this.f.optString("CustomGroupId"), this.f.optString("Type"));
            g gVar = this.h.c;
            gVar.y = 4;
            a aVar = gVar.z;
            if (aVar != null && aVar.getArguments() != null) {
                gVar.z.getArguments().putInt("OT_TV_FOCUSED_BTN", 1);
            }
            gVar.Q(map, true, false);
        }
        if (view.getId() == R.id.card_list_of_policy_link && AbstractC3617f4.a(i, keyEvent) == 21) {
            I activity = getActivity();
            com.onetrust.otpublishers.headless.UI.TVUI.datautils.c cVar = this.i;
            AbstractC3617f4.g(activity, cVar.o, cVar.p, cVar.j.y);
        }
        if (view.getId() == R.id.tv_sub_grp_back && AbstractC3617f4.a(i, keyEvent) == 21) {
            this.e.getPurposeConsentLocal(this.f.optString("CustomGroupId"));
            this.e.getPurposeLegitInterestLocal(this.f.optString("CustomGroupId"));
            k kVar = this.h;
            kVar.getChildFragmentManager().W();
            d dVar = kVar.o;
            if (dVar != null) {
                dVar.W.requestFocus();
            }
        }
        if (view.getId() != R.id.ot_iab_legal_desc_tv || keyEvent.getKeyCode() != 20) {
            if (view.getId() == R.id.card_list_of_sdks_sg && AbstractC3617f4.a(i, keyEvent) == 21) {
                ArrayList arrayList = new ArrayList();
                arrayList.add(this.f.optString("CustomGroupId"));
                this.h.H(arrayList);
            }
            return false;
        }
        k kVar2 = this.h;
        if (kVar2.f.getVisibility() == 0) {
            button = kVar2.f;
        } else if (kVar2.g.getVisibility() == 0) {
            button = kVar2.g;
        } else {
            if (kVar2.e.getVisibility() != 0) {
                return true;
            }
            button = kVar2.e;
        }
        button.requestFocus();
        return true;
    }

    @Override // com.onetrust.otpublishers.headless.UI.TVUI.adapter.j
    public final void a(JSONObject jSONObject) {
        this.h.I(jSONObject, true, false);
    }
}

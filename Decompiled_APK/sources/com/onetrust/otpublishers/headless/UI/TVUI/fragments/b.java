package com.onetrust.otpublishers.headless.UI.TVUI.fragments;

import android.R;
import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.Color;
import android.os.Bundle;
import android.view.KeyEvent;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.CheckBox;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import androidx.cardview.widget.CardView;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.I;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3617f4;
import com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK;
import com.onetrust.otpublishers.headless.Public.OTVendorListMode;
import com.onetrust.otpublishers.headless.Public.uiutils.OTVendorUtils;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public class b extends Fragment implements View.OnKeyListener, View.OnFocusChangeListener {
    public TextView a;
    public TextView b;
    public TextView c;
    public RelativeLayout d;
    public CardView e;
    public LinearLayout f;
    public LinearLayout g;
    public Context h;
    public OTPublishersHeadlessSDK i;
    public JSONObject j;
    public s k;
    public com.onetrust.otpublishers.headless.UI.TVUI.datautils.c l;
    public CheckBox m;
    public com.onetrust.otpublishers.headless.Internal.Event.a n;
    public boolean o = true;
    public ScrollView p;
    public String q;
    public com.onetrust.otpublishers.headless.UI.TVUI.datautils.e r;

    public final void G(String str, String str2) {
        this.m.setButtonTintList(new ColorStateList(new int[][]{new int[]{R.attr.state_checked}, new int[0]}, new int[]{Color.parseColor(str), Color.parseColor(str)}));
        this.c.setTextColor(Color.parseColor(str));
        this.f.setBackgroundColor(Color.parseColor(str2));
    }

    @Override // androidx.fragment.app.Fragment
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        this.h = getContext();
    }

    @Override // androidx.fragment.app.Fragment
    public final View onCreateView(LayoutInflater layoutInflater, ViewGroup viewGroup, Bundle bundle) {
        Context context = this.h;
        if (com.onetrust.otpublishers.headless.Internal.a.o(context)) {
            layoutInflater = layoutInflater.cloneInContext(new androidx.appcompat.view.d(context, com.quizlet.quizletandroid.R.style.Theme_AppCompat_Light_NoActionBar));
        }
        View viewInflate = layoutInflater.inflate(com.quizlet.quizletandroid.R.layout.ot_vendor_details_tv_fragment, viewGroup, false);
        this.r = com.onetrust.otpublishers.headless.UI.TVUI.datautils.e.a();
        this.a = (TextView) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.vendor_name_tv);
        this.b = (TextView) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.vendors_privacy_notice_tv);
        this.d = (RelativeLayout) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.vd_linearLyt_tv);
        this.e = (CardView) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.tv_vd_card_consent);
        this.f = (LinearLayout) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.vd_consent_lyt);
        this.g = (LinearLayout) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.vd_li_lyt);
        this.c = (TextView) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.vd_consent_label_tv);
        this.m = (CheckBox) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.tv_vd_consent_cb);
        this.p = (ScrollView) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.bg_main);
        this.m.setOnCheckedChangeListener(new com.google.android.material.chip.a(this, 1));
        this.e.setOnKeyListener(this);
        this.e.setOnFocusChangeListener(this);
        this.b.setOnKeyListener(this);
        this.b.setOnFocusChangeListener(this);
        this.g.setVisibility(8);
        this.r.c(this.j, OTVendorListMode.GOOGLE);
        this.l = com.onetrust.otpublishers.headless.UI.TVUI.datautils.c.i();
        this.p.setSmoothScrollingEnabled(true);
        this.a.setText(this.r.c);
        this.b.setText(this.r.f);
        this.c.setText(this.l.g);
        this.e.setVisibility(0);
        this.o = false;
        this.m.setChecked(this.j.optInt(OTVendorUtils.CONSENT_TYPE) == 1);
        this.q = AbstractC3617f4.j(this.l.a());
        String strL = this.l.l();
        this.a.setTextColor(Color.parseColor(strL));
        this.b.setTextColor(Color.parseColor(strL));
        this.d.setBackgroundColor(Color.parseColor(this.l.a()));
        this.e.setCardElevation(1.0f);
        G(strL, this.q);
        return viewInflate;
    }

    @Override // android.view.View.OnFocusChangeListener
    public final void onFocusChange(View view, boolean z) {
        TextView textView;
        String strL;
        CardView cardView;
        float f;
        if (view.getId() == com.quizlet.quizletandroid.R.id.tv_vd_card_consent) {
            if (z) {
                androidx.constraintlayout.motion.widget.n nVar = this.l.j.y;
                G((String) nVar.m, (String) nVar.l);
                cardView = this.e;
                f = 6.0f;
            } else {
                G(this.l.l(), this.q);
                cardView = this.e;
                f = 1.0f;
            }
            cardView.setCardElevation(f);
        }
        if (view.getId() == com.quizlet.quizletandroid.R.id.vendors_privacy_notice_tv) {
            if (z) {
                this.b.setBackgroundColor(Color.parseColor((String) this.l.j.y.l));
                textView = this.b;
                strL = (String) this.l.j.y.m;
            } else {
                this.b.setBackgroundColor(Color.parseColor(this.q));
                textView = this.b;
                strL = this.l.l();
            }
            textView.setTextColor(Color.parseColor(strL));
        }
    }

    @Override // android.view.View.OnKeyListener
    public final boolean onKey(View view, int i, KeyEvent keyEvent) {
        if (view.getId() == com.quizlet.quizletandroid.R.id.tv_vd_card_consent && AbstractC3617f4.a(i, keyEvent) == 21) {
            this.o = true;
            this.m.setChecked(!r0.isChecked());
        }
        if (view.getId() == com.quizlet.quizletandroid.R.id.vendors_privacy_notice_tv && AbstractC3617f4.a(i, keyEvent) == 21) {
            I activity = getActivity();
            com.onetrust.otpublishers.headless.UI.TVUI.datautils.e eVar = this.r;
            AbstractC3617f4.g(activity, eVar.d, eVar.f, this.l.j.y);
        }
        if (i == 4 && keyEvent.getAction() == 1) {
            this.k.p(23);
        }
        if (AbstractC3617f4.a(i, keyEvent) != 24) {
            return false;
        }
        this.k.p(24);
        return true;
    }
}

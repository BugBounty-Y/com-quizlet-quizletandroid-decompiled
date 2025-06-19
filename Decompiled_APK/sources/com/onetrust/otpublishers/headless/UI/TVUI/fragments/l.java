package com.onetrust.otpublishers.headless.UI.TVUI.fragments;

import android.R;
import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.Color;
import android.os.Bundle;
import android.view.KeyEvent;
import android.view.View;
import android.widget.CheckBox;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import androidx.cardview.widget.CardView;
import androidx.fragment.app.Fragment;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3617f4;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public class l extends Fragment implements View.OnKeyListener, View.OnFocusChangeListener {
    public TextView a;
    public TextView b;
    public TextView c;
    public TextView d;
    public TextView e;
    public RelativeLayout f;
    public CardView g;
    public CardView h;
    public LinearLayout i;
    public LinearLayout j;
    public Context k;
    public JSONObject l;
    public CheckBox m;
    public CheckBox n;
    public CheckBox o;
    public n p;
    public com.onetrust.otpublishers.headless.UI.TVUI.datautils.c q;
    public ScrollView r;
    public String s;
    public String t;
    public com.onetrust.otpublishers.headless.Internal.Event.a u;
    public OTPublishersHeadlessSDK v;

    public final void G(String str, String str2) {
        int[][] iArr = {new int[]{R.attr.state_checked}, new int[0]};
        int[] iArr2 = {Color.parseColor(str), Color.parseColor(str)};
        this.m.setButtonTintList(new ColorStateList(iArr, iArr2));
        this.n.setButtonTintList(new ColorStateList(iArr, iArr2));
        this.b.setTextColor(Color.parseColor(str));
        this.e.setTextColor(Color.parseColor(str));
        this.i.setBackgroundColor(Color.parseColor(str2));
    }

    public final void H(boolean z) {
        this.v.updateSDKConsentStatus(this.t, z);
        String str = this.t;
        androidx.compose.foundation.lazy.grid.m mVar = new androidx.compose.foundation.lazy.grid.m(24, 4);
        mVar.c = str;
        mVar.b = z ? 1 : 0;
        com.onetrust.otpublishers.headless.Internal.Event.a aVar = this.u;
        if (aVar != null) {
            aVar.a(mVar);
        } else {
            OTLogger.c("OneTrust", 6, "Error on sending UI events, listener set was found to be null.This could be because the activity has been recreated. \n Please set listener to get UI event callbacks.");
        }
    }

    public final void I(String str, String str2) {
        this.o.setButtonTintList(new ColorStateList(new int[][]{new int[]{R.attr.state_checked}, new int[0]}, new int[]{Color.parseColor(str), Color.parseColor(str)}));
        this.c.setTextColor(Color.parseColor(str));
        this.e.setTextColor(Color.parseColor(str));
        this.j.setBackgroundColor(Color.parseColor(str2));
    }

    @Override // androidx.fragment.app.Fragment
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        this.k = getContext();
    }

    /* JADX WARN: Removed duplicated region for block: B:27:0x0186  */
    @Override // androidx.fragment.app.Fragment
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final android.view.View onCreateView(android.view.LayoutInflater r13, android.view.ViewGroup r14, android.os.Bundle r15) {
        /*
            Method dump skipped, instructions count: 749
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.UI.TVUI.fragments.l.onCreateView(android.view.LayoutInflater, android.view.ViewGroup, android.os.Bundle):android.view.View");
    }

    @Override // android.view.View.OnFocusChangeListener
    public final void onFocusChange(View view, boolean z) {
        if (view.getId() == com.quizlet.quizletandroid.R.id.tv_sdk_card_consent) {
            if (z) {
                androidx.constraintlayout.motion.widget.n nVar = this.q.j.y;
                G((String) nVar.m, (String) nVar.l);
                this.g.setCardElevation(6.0f);
            } else {
                G(this.q.l(), this.s);
                this.g.setCardElevation(1.0f);
            }
        }
        if (view.getId() == com.quizlet.quizletandroid.R.id.tv_sdk_card_off) {
            if (!z) {
                I(this.q.l(), this.s);
                this.h.setCardElevation(1.0f);
            } else {
                androidx.constraintlayout.motion.widget.n nVar2 = this.q.j.y;
                I((String) nVar2.m, (String) nVar2.l);
                this.h.setCardElevation(6.0f);
            }
        }
    }

    @Override // android.view.View.OnKeyListener
    public final boolean onKey(View view, int i, KeyEvent keyEvent) {
        com.onetrust.otpublishers.headless.UI.TVUI.adapter.r rVar;
        if (i == 4 && keyEvent.getAction() == 1) {
            this.p.getChildFragmentManager().W();
        }
        if (AbstractC3617f4.a(i, keyEvent) == 24 && (rVar = this.p.l) != null) {
            rVar.notifyDataSetChanged();
        }
        if (this.q.p()) {
            if (view.getId() == com.quizlet.quizletandroid.R.id.tv_sdk_card_consent && AbstractC3617f4.a(i, keyEvent) == 21) {
                boolean z = !this.m.isChecked();
                this.m.setChecked(z);
                H(z);
            }
        } else if (view.getId() == com.quizlet.quizletandroid.R.id.tv_sdk_card_consent && AbstractC3617f4.a(i, keyEvent) == 21) {
            if (!this.n.isChecked()) {
                H(true);
                this.n.setChecked(true);
                this.o.setChecked(false);
                return false;
            }
        } else if (view.getId() == com.quizlet.quizletandroid.R.id.tv_sdk_card_off && AbstractC3617f4.a(i, keyEvent) == 21 && !this.o.isChecked()) {
            H(false);
            this.n.setChecked(false);
            this.o.setChecked(true);
            return false;
        }
        return false;
    }
}

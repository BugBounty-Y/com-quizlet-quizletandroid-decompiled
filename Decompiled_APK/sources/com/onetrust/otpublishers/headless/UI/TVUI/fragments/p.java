package com.onetrust.otpublishers.headless.UI.TVUI.fragments;

import android.R;
import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.Color;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.widget.CheckBox;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import androidx.cardview.widget.CardView;
import androidx.compose.ui.node.B;
import androidx.fragment.app.Fragment;
import androidx.recyclerview.widget.RecyclerView;
import com.google.android.gms.internal.mlkit_vision_document_scanner.W;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK;
import okhttp3.A;
import okhttp3.z;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import retrofit2.C5177b;

/* loaded from: classes2.dex */
public class p extends Fragment implements View.OnKeyListener, View.OnFocusChangeListener {
    public ScrollView B;
    public String C;
    public com.onetrust.otpublishers.headless.UI.TVUI.datautils.e D;
    public TextView a;
    public TextView b;
    public TextView c;
    public TextView d;
    public TextView e;
    public TextView f;
    public TextView g;
    public TextView h;
    public RelativeLayout i;
    public CardView j;
    public CardView k;
    public LinearLayout l;
    public LinearLayout m;
    public View n;
    public RecyclerView o;
    public Context p;
    public OTPublishersHeadlessSDK q;
    public JSONObject r;
    public s s;
    public com.onetrust.otpublishers.headless.UI.TVUI.datautils.c t;
    public CheckBox u;
    public CheckBox v;
    public JSONObject w;
    public com.onetrust.otpublishers.headless.UI.TVUI.adapter.e x;
    public com.onetrust.otpublishers.headless.Internal.Event.a y;
    public boolean z = true;
    public boolean A = true;
    public int E = -1;

    public static void I(JSONArray jSONArray, String str, JSONObject jSONObject, boolean z, boolean z2, JSONObject jSONObject2, String str2) throws JSONException {
        if (jSONArray != null) {
            try {
                if (jSONArray.length() > 0) {
                    jSONObject.put(str, 1);
                    int i = 0;
                    while (i < jSONArray.length()) {
                        JSONObject jSONObject3 = jSONObject;
                        boolean z3 = z;
                        boolean z4 = z2;
                        JSONObject jSONObject4 = jSONObject2;
                        String str3 = str2;
                        K(jSONObject3, z4, jSONArray.optJSONObject(i), z3, jSONObject4, str3);
                        i++;
                        jSONObject = jSONObject3;
                        z2 = z4;
                        z = z3;
                        jSONObject2 = jSONObject4;
                        str2 = str3;
                    }
                }
            } catch (JSONException e) {
                W.a("exception thrown while constructing vendor purpose data, err: ", e, "OneTrust", 6);
            }
        }
    }

    public static void J(JSONObject jSONObject, JSONObject jSONObject2, com.onetrust.otpublishers.headless.UI.TVUI.datautils.e eVar) throws JSONException {
        String string = jSONObject.getString("stdRetention");
        if (com.onetrust.otpublishers.headless.Internal.a.j(string) || Integer.parseInt(string) < 0) {
            return;
        }
        StringBuilder sb = new StringBuilder();
        B.u(sb, eVar.A, " (", string, " ");
        sb.append(eVar.B);
        sb.append(")");
        jSONObject2.put(sb.toString(), 5);
    }

    public static void K(JSONObject jSONObject, boolean z, JSONObject jSONObject2, boolean z2, JSONObject jSONObject3, String str) throws JSONException {
        if (retrofit2.adapter.rxjava3.d.o(jSONObject2)) {
            return;
        }
        String string = z ? jSONObject2.toString() : jSONObject2.optString("name");
        if (jSONObject3 != null && jSONObject2.has("id")) {
            String string2 = jSONObject2.getString("id");
            if (jSONObject3.has(string2) && !com.onetrust.otpublishers.headless.Internal.a.j(str)) {
                String strOptString = jSONObject3.optString(string2);
                if (!com.onetrust.otpublishers.headless.Internal.a.j(strOptString) && Integer.parseInt(strOptString) >= 0) {
                    string = string + " (" + strOptString + " " + str + ")";
                }
            }
        }
        jSONObject.put(string, z ? z2 ? 4 : 3 : 2);
    }

    /* JADX WARN: Removed duplicated region for block: B:18:0x0062  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final org.json.JSONObject G(com.onetrust.otpublishers.headless.UI.TVUI.datautils.e r12, org.json.JSONObject r13) throws org.json.JSONException {
        /*
            r11 = this;
            java.lang.String r0 = "stdRetention"
            org.json.JSONObject r3 = new org.json.JSONObject
            r3.<init>()
            org.json.JSONObject r1 = r11.r
            if (r1 == 0) goto Ld8
            java.lang.String r2 = "dataRetention"
            org.json.JSONObject r8 = r1.optJSONObject(r2)
            com.onetrust.otpublishers.headless.UI.TVUI.datautils.c r1 = r11.t
            java.lang.String r1 = r1.f
            boolean r1 = com.onetrust.otpublishers.headless.Internal.a.l(r1)
            java.lang.String r9 = "specialPurposes"
            java.lang.String r10 = "purposes"
            if (r1 == 0) goto L62
            org.json.JSONObject r1 = r11.r
            java.lang.String r2 = "dataDeclaration"
            org.json.JSONArray r1 = r1.optJSONArray(r2)
            java.lang.String r2 = r12.y
            r4 = 0
            r5 = 0
            r6 = 0
            r7 = 0
            I(r1, r2, r3, r4, r5, r6, r7)
            if (r8 == 0) goto L55
            java.lang.String r1 = r12.z     // Catch: org.json.JSONException -> L4c
            r2 = 1
            r3.put(r1, r2)     // Catch: org.json.JSONException -> L4c
            boolean r1 = r8.has(r0)     // Catch: org.json.JSONException -> L4c
            if (r1 == 0) goto L55
            java.lang.String r0 = r8.getString(r0)     // Catch: org.json.JSONException -> L4c
            boolean r0 = com.onetrust.otpublishers.headless.Internal.a.j(r0)     // Catch: org.json.JSONException -> L4c
            if (r0 != 0) goto L55
            J(r8, r3, r12)     // Catch: org.json.JSONException -> L4c
            goto L55
        L4c:
            r0 = move-exception
            java.lang.String r1 = "Error on updating data retention, error = "
            java.lang.String r2 = "TV Vendor"
            r4 = 6
            com.google.android.gms.measurement.internal.Z.p(r1, r0, r2, r4)
        L55:
            if (r8 == 0) goto L62
            org.json.JSONObject r0 = r8.optJSONObject(r10)
            org.json.JSONObject r1 = r8.optJSONObject(r9)
            r6 = r0
            r0 = r1
            goto L64
        L62:
            r0 = 0
            r6 = r0
        L64:
            org.json.JSONObject r1 = r11.r
            org.json.JSONArray r1 = r1.optJSONArray(r10)
            java.lang.String r2 = r12.k
            java.lang.String r7 = r12.B
            r4 = 0
            r5 = 0
            I(r1, r2, r3, r4, r5, r6, r7)
            org.json.JSONObject r1 = r11.r
            org.json.JSONArray r1 = r1.optJSONArray(r9)
            java.lang.String r2 = r12.n
            java.lang.String r7 = r12.B
            r6 = r0
            I(r1, r2, r3, r4, r5, r6, r7)
            org.json.JSONObject r0 = r11.r
            java.lang.String r1 = "legIntPurposes"
            org.json.JSONArray r1 = r0.optJSONArray(r1)
            java.lang.String r2 = r12.l
            r6 = 0
            r7 = 0
            I(r1, r2, r3, r4, r5, r6, r7)
            java.lang.String r0 = "disclosures"
            org.json.JSONArray r1 = r13.optJSONArray(r0)
            java.lang.String r2 = r12.j
            r5 = 1
            I(r1, r2, r3, r4, r5, r6, r7)
            java.lang.String r0 = "domains"
            org.json.JSONArray r1 = r13.optJSONArray(r0)
            java.lang.String r2 = r12.w
            r4 = 1
            I(r1, r2, r3, r4, r5, r6, r7)
            org.json.JSONObject r13 = r11.r
            java.lang.String r0 = "specialFeatures"
            org.json.JSONArray r1 = r13.optJSONArray(r0)
            java.lang.String r2 = r12.o
            r4 = 0
            r5 = 0
            I(r1, r2, r3, r4, r5, r6, r7)
            org.json.JSONObject r13 = r11.r
            java.lang.String r0 = "features"
            org.json.JSONArray r1 = r13.optJSONArray(r0)
            java.lang.String r2 = r12.m
            I(r1, r2, r3, r4, r5, r6, r7)
            java.lang.StringBuilder r12 = new java.lang.StringBuilder
            java.lang.String r13 = "vendor purposes:"
            r12.<init>(r13)
            r12.append(r3)
            java.lang.String r12 = r12.toString()
            java.lang.String r13 = "OneTrust"
            r0 = 2
            com.onetrust.otpublishers.headless.Internal.Log.OTLogger.c(r13, r0, r12)
        Ld8:
            return r3
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.UI.TVUI.fragments.p.G(com.onetrust.otpublishers.headless.UI.TVUI.datautils.e, org.json.JSONObject):org.json.JSONObject");
    }

    public final void H(String str, String str2) {
        this.u.setButtonTintList(new ColorStateList(new int[][]{new int[]{R.attr.state_checked}, new int[0]}, new int[]{Color.parseColor(str), Color.parseColor(str)}));
        this.f.setTextColor(Color.parseColor(str));
        this.l.setBackgroundColor(Color.parseColor(str2));
    }

    public final void L() {
        View view;
        com.onetrust.otpublishers.headless.UI.TVUI.datautils.e eVar = this.D;
        if (eVar != null && !com.onetrust.otpublishers.headless.Internal.a.j(eVar.q)) {
            String str = this.D.q;
            OTLogger.c("TV Vendor", 3, "IAB Vendor Disclosure API called ");
            com.quizlet.data.repository.explanations.textbook.a aVar = new com.quizlet.data.repository.explanations.textbook.a(8);
            aVar.c("https://geolocation.1trust.app/");
            aVar.b(new C5177b(2));
            aVar.a = new A(new z());
            ((com.onetrust.otpublishers.headless.Internal.Network.a) aVar.e().b(com.onetrust.otpublishers.headless.Internal.Network.a.class)).a(str).j(new com.quizlet.data.repository.school.membership.a(this, 27));
        }
        TextView textView = this.b;
        if (textView == null || com.onetrust.otpublishers.headless.Internal.a.j(textView.getText().toString())) {
            TextView textView2 = this.c;
            if (textView2 == null || com.onetrust.otpublishers.headless.Internal.a.j(textView2.getText().toString())) {
                CardView cardView = this.j;
                if (cardView == null || cardView.getVisibility() != 0) {
                    CardView cardView2 = this.k;
                    if (cardView2 == null || cardView2.getVisibility() != 0) {
                        return;
                    } else {
                        view = this.k;
                    }
                } else {
                    view = this.j;
                }
            } else {
                view = this.c;
            }
        } else {
            view = this.b;
        }
        view.requestFocus();
    }

    public final void M(String str, String str2) {
        this.v.setButtonTintList(new ColorStateList(new int[][]{new int[]{R.attr.state_checked}, new int[0]}, new int[]{Color.parseColor(str), Color.parseColor(str)}));
        this.g.setTextColor(Color.parseColor(str));
        this.m.setBackgroundColor(Color.parseColor(str2));
    }

    @Override // androidx.fragment.app.Fragment
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        this.p = getContext();
    }

    /* JADX WARN: Removed duplicated region for block: B:16:0x019d  */
    /* JADX WARN: Removed duplicated region for block: B:17:0x01a7  */
    /* JADX WARN: Removed duplicated region for block: B:20:0x01b6  */
    /* JADX WARN: Removed duplicated region for block: B:21:0x01c5  */
    /* JADX WARN: Removed duplicated region for block: B:24:0x01fb  */
    @Override // androidx.fragment.app.Fragment
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final android.view.View onCreateView(android.view.LayoutInflater r6, android.view.ViewGroup r7, android.os.Bundle r8) {
        /*
            Method dump skipped, instructions count: 702
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.UI.TVUI.fragments.p.onCreateView(android.view.LayoutInflater, android.view.ViewGroup, android.os.Bundle):android.view.View");
    }

    @Override // android.view.View.OnFocusChangeListener
    public final void onFocusChange(View view, boolean z) {
        TextView textView;
        String strL;
        TextView textView2;
        String strL2;
        if (view.getId() == com.quizlet.quizletandroid.R.id.tv_vd_card_consent) {
            if (z) {
                androidx.constraintlayout.motion.widget.n nVar = this.t.j.y;
                H((String) nVar.m, (String) nVar.l);
                this.j.setCardElevation(6.0f);
            } else {
                H(this.t.l(), this.C);
                this.j.setCardElevation(1.0f);
            }
        }
        if (view.getId() == com.quizlet.quizletandroid.R.id.tv_vd_card_li) {
            if (z) {
                androidx.constraintlayout.motion.widget.n nVar2 = this.t.j.y;
                M((String) nVar2.m, (String) nVar2.l);
                this.k.setCardElevation(6.0f);
            } else {
                M(this.t.l(), this.C);
                this.k.setCardElevation(1.0f);
            }
        }
        if (view.getId() == com.quizlet.quizletandroid.R.id.vendors_privacy_notice_tv) {
            if (z) {
                this.b.setBackgroundColor(Color.parseColor((String) this.t.j.y.l));
                textView2 = this.b;
                strL2 = (String) this.t.j.y.m;
            } else {
                this.b.setBackgroundColor(Color.parseColor(this.C));
                textView2 = this.b;
                strL2 = this.t.l();
            }
            textView2.setTextColor(Color.parseColor(strL2));
        }
        if (view.getId() == com.quizlet.quizletandroid.R.id.vendors_privacy_li_notice_tv) {
            if (z) {
                this.c.setBackgroundColor(Color.parseColor((String) this.t.j.y.l));
                textView = this.c;
                strL = (String) this.t.j.y.m;
            } else {
                this.c.setBackgroundColor(Color.parseColor(this.C));
                textView = this.c;
                strL = this.t.l();
            }
            textView.setTextColor(Color.parseColor(strL));
        }
        if (view.getId() == com.quizlet.quizletandroid.R.id.lifespan_desc_tv && z && this.E <= 1) {
            new Handler(Looper.getMainLooper()).post(new com.google.firebase.crashlytics.internal.metadata.q(this, 4));
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:16:0x003f  */
    /* JADX WARN: Removed duplicated region for block: B:21:0x0062  */
    /* JADX WARN: Removed duplicated region for block: B:24:0x0072  */
    /* JADX WARN: Removed duplicated region for block: B:29:0x009a  */
    /* JADX WARN: Removed duplicated region for block: B:37:0x00b7  */
    /* JADX WARN: Removed duplicated region for block: B:39:0x00bd A[RETURN] */
    @Override // android.view.View.OnKeyListener
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean onKey(android.view.View r8, int r9, android.view.KeyEvent r10) {
        /*
            r7 = this;
            int r0 = r8.getId()
            r1 = 2131429770(0x7f0b098a, float:1.8481222E38)
            r2 = 21
            r3 = 1
            if (r0 != r1) goto L1b
            int r0 = com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3617f4.a(r9, r10)
            if (r0 != r2) goto L1b
            r7.z = r3
            android.widget.CheckBox r0 = r7.u
        L16:
            boolean r1 = r0.isChecked()
            goto L2f
        L1b:
            int r0 = r8.getId()
            r1 = 2131429771(0x7f0b098b, float:1.8481224E38)
            if (r0 != r1) goto L33
            int r0 = com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3617f4.a(r9, r10)
            if (r0 != r2) goto L33
            r7.A = r3
            android.widget.CheckBox r0 = r7.v
            goto L16
        L2f:
            r1 = r1 ^ r3
            r0.setChecked(r1)
        L33:
            com.onetrust.otpublishers.headless.UI.TVUI.datautils.e r0 = r7.D
            java.lang.String r0 = r0.d
            boolean r0 = com.onetrust.otpublishers.headless.Internal.a.j(r0)
            r1 = 8
            if (r0 != 0) goto L62
            int r0 = r8.getId()
            r4 = 2131429843(0x7f0b09d3, float:1.848137E38)
            if (r0 != r4) goto L67
            int r0 = com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3617f4.a(r9, r10)
            if (r0 != r2) goto L67
            androidx.fragment.app.I r0 = r7.getActivity()
            com.onetrust.otpublishers.headless.UI.TVUI.datautils.e r4 = r7.D
            java.lang.String r5 = r4.d
            java.lang.String r4 = r4.f
            com.onetrust.otpublishers.headless.UI.TVUI.datautils.c r6 = r7.t
            com.onetrust.otpublishers.headless.UI.UIProperty.e r6 = r6.j
            androidx.constraintlayout.motion.widget.n r6 = r6.y
            com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3617f4.g(r0, r5, r4, r6)
            goto L67
        L62:
            android.widget.TextView r0 = r7.b
            r0.setVisibility(r1)
        L67:
            com.onetrust.otpublishers.headless.UI.TVUI.datautils.e r0 = r7.D
            java.lang.String r0 = r0.e
            boolean r0 = com.onetrust.otpublishers.headless.Internal.a.j(r0)
            r4 = 0
            if (r0 != 0) goto L9a
            int r8 = r8.getId()
            r0 = 2131429841(0x7f0b09d1, float:1.8481366E38)
            if (r8 != r0) goto L9f
            int r8 = com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3617f4.a(r9, r10)
            if (r8 != r2) goto L9f
            android.widget.TextView r8 = r7.c
            r8.setVisibility(r4)
            androidx.fragment.app.I r8 = r7.getActivity()
            com.onetrust.otpublishers.headless.UI.TVUI.datautils.e r0 = r7.D
            java.lang.String r1 = r0.e
            java.lang.String r0 = r0.g
            com.onetrust.otpublishers.headless.UI.TVUI.datautils.c r2 = r7.t
            com.onetrust.otpublishers.headless.UI.UIProperty.e r2 = r2.j
            androidx.constraintlayout.motion.widget.n r2 = r2.y
            com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3617f4.g(r8, r1, r0, r2)
            goto L9f
        L9a:
            android.widget.TextView r8 = r7.c
            r8.setVisibility(r1)
        L9f:
            r8 = 4
            if (r9 != r8) goto Laf
            int r8 = r10.getAction()
            if (r8 != r3) goto Laf
            com.onetrust.otpublishers.headless.UI.TVUI.fragments.s r8 = r7.s
            r0 = 23
            r8.p(r0)
        Laf:
            int r8 = com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3617f4.a(r9, r10)
            r9 = 24
            if (r8 != r9) goto Lbd
            com.onetrust.otpublishers.headless.UI.TVUI.fragments.s r8 = r7.s
            r8.p(r9)
            return r3
        Lbd:
            return r4
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.UI.TVUI.fragments.p.onKey(android.view.View, int, android.view.KeyEvent):boolean");
    }
}

package com.onetrust.otpublishers.headless.UI.TVUI.fragments;

import android.content.SharedPreferences;
import android.graphics.Color;
import android.os.Bundle;
import android.view.KeyEvent;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.cardview.widget.CardView;
import androidx.compose.ui.node.B;
import androidx.fragment.app.AbstractC1136h0;
import androidx.fragment.app.C1121a;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.I;
import androidx.lifecycle.A;
import androidx.lifecycle.H;
import androidx.lifecycle.J;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3581b0;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3605e0;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3617f4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3649j4;
import com.google.android.gms.measurement.internal.Z;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.onetrust.otpublishers.headless.Public.DataModel.OTConfiguration;
import com.onetrust.otpublishers.headless.Public.DataModel.OTCustomConfigurator;
import com.onetrust.otpublishers.headless.Public.DataModel.OTProxyType;
import com.onetrust.otpublishers.headless.Public.Keys.OTFragmentTags;
import com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public class k extends Fragment implements View.OnKeyListener, View.OnFocusChangeListener {
    public I a;
    public OTPublishersHeadlessSDK b;
    public g c;
    public com.onetrust.otpublishers.headless.Internal.Event.a d;
    public Button e;
    public Button f;
    public Button g;
    public Button h;
    public RecyclerView i;
    public com.onetrust.otpublishers.headless.UI.TVUI.datautils.c j;
    public RelativeLayout k;
    public LinearLayout l;
    public ImageView m;
    public ImageView n;
    public d o;
    public i p;
    public c q;
    public View r;
    public com.onetrust.otpublishers.headless.UI.TVUI.adapter.i s;
    public boolean t;
    public OTConfiguration u;

    public final JSONArray G(JSONArray jSONArray) throws JSONException {
        String str;
        JSONObject jSONObject = new JSONObject();
        JSONArray jSONArray2 = new JSONArray();
        if (jSONArray != null) {
            try {
                String str2 = (String) this.j.j.k.g;
                if (str2 == null) {
                    str2 = "";
                }
                jSONObject.put("GroupName", str2);
                String str3 = (String) this.j.j.l.g;
                if (str3 == null) {
                    str3 = "";
                }
                jSONObject.put("GroupDescription", str3);
                jSONObject.put("isAlertNotice", true);
                jSONArray2.put(jSONObject);
                if (this.j.e) {
                    JSONObject jSONObject2 = new JSONObject();
                    com.onetrust.otpublishers.headless.UI.UIProperty.g gVar = (com.onetrust.otpublishers.headless.UI.UIProperty.g) com.onetrust.otpublishers.headless.UI.TVUI.datautils.d.a().f;
                    if (gVar == null || (str = (String) ((androidx.navigation.internal.m) gVar.r.b).g) == null) {
                        str = "";
                    }
                    jSONObject2.put("GroupName", str);
                    jSONObject2.put("GroupDescription", "");
                    jSONObject2.put("IS_PARTNERS_LINK", true);
                    jSONArray2.put(jSONObject2);
                }
                for (int i = 0; i < jSONArray.length(); i++) {
                    jSONArray2.put(jSONArray.getJSONObject(i));
                }
            } catch (JSONException e) {
                Z.o("Exception while setting alert notice text, err : ", e, "OneTrust");
                return jSONArray;
            }
        }
        return jSONArray2;
    }

    public final void H(ArrayList arrayList) {
        g gVar = this.c;
        gVar.y = 6;
        a aVar = gVar.z;
        if (aVar != null && aVar.getArguments() != null) {
            gVar.z.getArguments().putInt("OT_TV_FOCUSED_BTN", 1);
        }
        assistantMode.utils.studiableMetadata.b bVar = gVar.x;
        androidx.compose.foundation.lazy.grid.m mVar = new androidx.compose.foundation.lazy.grid.m(25, 4);
        com.onetrust.otpublishers.headless.Internal.Event.a aVar2 = gVar.v;
        bVar.getClass();
        assistantMode.utils.studiableMetadata.b.y(mVar, aVar2);
        com.onetrust.otpublishers.headless.Internal.Event.a aVar3 = gVar.v;
        OTPublishersHeadlessSDK oTPublishersHeadlessSDK = gVar.u;
        OTConfiguration oTConfiguration = gVar.A;
        n nVar = new n();
        Bundle bundle = new Bundle();
        bundle.putString("TV_PC_CONTENT", OTFragmentTags.OT_SDK_LIST_FRAGMENT_TAG);
        nVar.setArguments(bundle);
        nVar.b = gVar;
        nVar.k = arrayList;
        nVar.z = oTPublishersHeadlessSDK;
        nVar.A = aVar3;
        nVar.C = oTConfiguration;
        AbstractC1136h0 childFragmentManager = gVar.getChildFragmentManager();
        childFragmentManager.getClass();
        C1121a c1121a = new C1121a(childFragmentManager);
        c1121a.l(R.id.tv_main_lyt, nVar, null);
        c1121a.d(OTFragmentTags.OT_VENDOR_LIST_FRAGMENT_TAG);
        c1121a.g();
    }

    public final void I(JSONObject jSONObject, boolean z, boolean z2) {
        boolean z3;
        if (z2) {
            OTPublishersHeadlessSDK oTPublishersHeadlessSDK = this.b;
            c cVar = new c();
            Bundle bundle = new Bundle();
            bundle.putString("TVIllustration", OTFragmentTags.OT_PREFERENCE_CENTER_DETAILS_FRAGMENT_TAG);
            cVar.setArguments(bundle);
            z3 = cVar.f != null;
            cVar.f = jSONObject;
            if (z3) {
                cVar.G();
            }
            cVar.h = this;
            cVar.e = oTPublishersHeadlessSDK;
            this.q = cVar;
            AbstractC1136h0 childFragmentManager = getChildFragmentManager();
            C1121a c1121aB = B.b(childFragmentManager, childFragmentManager);
            c1121aB.l(R.id.ot_pc_detail_container, this.q, null);
            c1121aB.d(null);
            c1121aB.g();
            final int i = 1;
            this.q.getLifecycle().a(new H(this) { // from class: com.onetrust.otpublishers.headless.UI.TVUI.fragments.j
                public final /* synthetic */ k b;

                {
                    this.b = this;
                }

                @Override // androidx.lifecycle.H
                public final void d(J j, A a) {
                    View view;
                    switch (i) {
                        case 0:
                            k kVar = this.b;
                            kVar.getClass();
                            if (a.compareTo(A.ON_RESUME) == 0) {
                                kVar.g.clearFocus();
                                kVar.f.clearFocus();
                                kVar.e.clearFocus();
                                i iVar = kVar.p;
                                CardView cardView = iVar.t;
                                if (cardView == null || cardView.getVisibility() != 0) {
                                    CardView cardView2 = iVar.u;
                                    if (cardView2 == null || cardView2.getVisibility() != 0) {
                                        view = iVar.b;
                                        if (view == null) {
                                        }
                                    } else {
                                        view = iVar.u;
                                    }
                                } else {
                                    view = iVar.t;
                                }
                                view.requestFocus();
                                break;
                            }
                            break;
                        default:
                            k kVar2 = this.b;
                            kVar2.getClass();
                            if (a.compareTo(A.ON_RESUME) == 0) {
                                kVar2.g.clearFocus();
                                kVar2.f.clearFocus();
                                kVar2.e.clearFocus();
                                TextView textView = kVar2.q.b;
                                if (textView != null) {
                                    textView.requestFocus();
                                    break;
                                }
                            }
                            break;
                    }
                }
            });
            return;
        }
        com.onetrust.otpublishers.headless.Internal.Event.a aVar = this.d;
        OTPublishersHeadlessSDK oTPublishersHeadlessSDK2 = this.b;
        i iVar = new i();
        Bundle bundle2 = new Bundle();
        bundle2.putString("GroupDetails", OTFragmentTags.OT_PREFERENCE_CENTER_DETAILS_FRAGMENT_TAG);
        iVar.setArguments(bundle2);
        z3 = iVar.l != null;
        iVar.l = jSONObject;
        if (z3) {
            iVar.J();
        }
        iVar.n = aVar;
        iVar.o = this;
        iVar.p = z;
        iVar.k = oTPublishersHeadlessSDK2;
        this.p = iVar;
        AbstractC1136h0 childFragmentManager2 = getChildFragmentManager();
        C1121a c1121aB2 = B.b(childFragmentManager2, childFragmentManager2);
        c1121aB2.l(R.id.ot_pc_detail_container, this.p, null);
        c1121aB2.d(null);
        c1121aB2.g();
        final int i2 = 0;
        this.p.getLifecycle().a(new H(this) { // from class: com.onetrust.otpublishers.headless.UI.TVUI.fragments.j
            public final /* synthetic */ k b;

            {
                this.b = this;
            }

            @Override // androidx.lifecycle.H
            public final void d(J j, A a) {
                View view;
                switch (i2) {
                    case 0:
                        k kVar = this.b;
                        kVar.getClass();
                        if (a.compareTo(A.ON_RESUME) == 0) {
                            kVar.g.clearFocus();
                            kVar.f.clearFocus();
                            kVar.e.clearFocus();
                            i iVar2 = kVar.p;
                            CardView cardView = iVar2.t;
                            if (cardView == null || cardView.getVisibility() != 0) {
                                CardView cardView2 = iVar2.u;
                                if (cardView2 == null || cardView2.getVisibility() != 0) {
                                    view = iVar2.b;
                                    if (view == null) {
                                    }
                                } else {
                                    view = iVar2.u;
                                }
                            } else {
                                view = iVar2.t;
                            }
                            view.requestFocus();
                            break;
                        }
                        break;
                    default:
                        k kVar2 = this.b;
                        kVar2.getClass();
                        if (a.compareTo(A.ON_RESUME) == 0) {
                            kVar2.g.clearFocus();
                            kVar2.f.clearFocus();
                            kVar2.e.clearFocus();
                            TextView textView = kVar2.q.b;
                            if (textView != null) {
                                textView.requestFocus();
                                break;
                            }
                        }
                        break;
                }
            }
        });
    }

    /* JADX WARN: Removed duplicated region for block: B:13:0x0080  */
    /* JADX WARN: Removed duplicated region for block: B:15:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void J(boolean r8, androidx.constraintlayout.motion.widget.n r9) {
        /*
            r7 = this;
            java.lang.Object r0 = r9.n
            r2 = r0
            java.lang.String r2 = (java.lang.String) r2
            java.lang.Object r0 = r9.l
            r3 = r0
            java.lang.String r3 = (java.lang.String) r3
            com.onetrust.otpublishers.headless.UI.TVUI.datautils.c r0 = r7.j
            java.lang.String r4 = r0.a()
            com.onetrust.otpublishers.headless.UI.TVUI.datautils.c r0 = r7.j
            java.lang.String r5 = r0.l()
            android.widget.ImageView r6 = r7.n
            r1 = r8
            android.graphics.drawable.GradientDrawable r8 = com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3617f4.b(r1, r2, r3, r4, r5, r6)
            if (r1 == 0) goto L56
            java.lang.Object r0 = r9.l
            java.lang.String r0 = (java.lang.String) r0
            boolean r0 = com.onetrust.otpublishers.headless.Internal.a.j(r0)
            if (r0 != 0) goto L76
            java.lang.Object r0 = r9.m
            java.lang.String r0 = (java.lang.String) r0
            boolean r0 = com.onetrust.otpublishers.headless.Internal.a.j(r0)
            if (r0 != 0) goto L76
            android.widget.ImageView r0 = r7.n
            android.graphics.drawable.Drawable r0 = r0.getBackground()
            java.lang.Object r1 = r9.l
            java.lang.String r1 = (java.lang.String) r1
            int r1 = android.graphics.Color.parseColor(r1)
            r0.setTint(r1)
            android.widget.ImageView r0 = r7.n
            android.graphics.drawable.Drawable r0 = r0.getDrawable()
            java.lang.Object r1 = r9.m
            java.lang.String r1 = (java.lang.String) r1
        L4e:
            int r1 = android.graphics.Color.parseColor(r1)
            r0.setTint(r1)
            goto L76
        L56:
            android.widget.ImageView r0 = r7.n
            android.graphics.drawable.Drawable r0 = r0.getBackground()
            com.onetrust.otpublishers.headless.UI.TVUI.datautils.c r1 = r7.j
            java.lang.String r1 = r1.l()
            int r1 = android.graphics.Color.parseColor(r1)
            r0.setTint(r1)
            android.widget.ImageView r0 = r7.n
            android.graphics.drawable.Drawable r0 = r0.getDrawable()
            com.onetrust.otpublishers.headless.UI.TVUI.datautils.c r1 = r7.j
            java.lang.String r1 = r1.a()
            goto L4e
        L76:
            java.io.Serializable r9 = r9.g
            java.lang.String r9 = (java.lang.String) r9
            boolean r9 = com.onetrust.otpublishers.headless.Internal.a.j(r9)
            if (r9 != 0) goto L85
            android.widget.ImageView r9 = r7.n
            r9.setBackground(r8)
        L85:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.UI.TVUI.fragments.k.J(boolean, androidx.constraintlayout.motion.widget.n):void");
    }

    public final void a(JSONObject jSONObject) {
        if (jSONObject != null) {
            com.onetrust.otpublishers.headless.Internal.Event.a aVar = this.d;
            OTPublishersHeadlessSDK oTPublishersHeadlessSDK = this.b;
            d dVar = new d();
            Bundle bundle = new Bundle();
            bundle.putString("GroupDetails", "GroupDetails");
            dVar.setArguments(bundle);
            boolean z = dVar.u != null;
            dVar.u = jSONObject;
            if (z) {
                dVar.K();
            }
            dVar.w = aVar;
            dVar.x = this;
            dVar.k = oTPublishersHeadlessSDK;
            this.o = dVar;
            AbstractC1136h0 childFragmentManager = getChildFragmentManager();
            C1121a c1121aB = B.b(childFragmentManager, childFragmentManager);
            c1121aB.l(R.id.ot_pc_detail_container, this.o, null);
            c1121aB.d(null);
            c1121aB.g();
        }
    }

    @Override // androidx.fragment.app.Fragment
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        this.a = getActivity();
        this.j = com.onetrust.otpublishers.headless.UI.TVUI.datautils.c.i();
    }

    @Override // androidx.fragment.app.Fragment
    public final View onCreateView(LayoutInflater layoutInflater, ViewGroup viewGroup, Bundle bundle) {
        StringBuilder sb;
        I i = this.a;
        if (com.onetrust.otpublishers.headless.Internal.a.o(i)) {
            layoutInflater = layoutInflater.cloneInContext(new androidx.appcompat.view.d(i, R.style.Theme_AppCompat_Light_NoActionBar));
        }
        View viewInflate = layoutInflater.inflate(R.layout.ot_pc_tvfragment, viewGroup, false);
        RecyclerView recyclerView = (RecyclerView) viewInflate.findViewById(R.id.tv_grp_list);
        this.i = recyclerView;
        recyclerView.setHasFixedSize(true);
        this.i.setLayoutManager(new LinearLayoutManager(getActivity()));
        this.e = (Button) viewInflate.findViewById(R.id.tv_btn_confirm);
        this.f = (Button) viewInflate.findViewById(R.id.tv_btn_accept_pc);
        this.g = (Button) viewInflate.findViewById(R.id.tv_btn_reject_pc);
        this.h = (Button) viewInflate.findViewById(R.id.ot_tv_pc_close_button);
        this.k = (RelativeLayout) viewInflate.findViewById(R.id.tv_pc_lyt);
        this.l = (LinearLayout) viewInflate.findViewById(R.id.tv_btn_layout);
        this.m = (ImageView) viewInflate.findViewById(R.id.ot_tv_pc_logo);
        this.n = (ImageView) viewInflate.findViewById(R.id.ot_tv_pc_close);
        this.r = viewInflate.findViewById(R.id.ot_pc_list_div_tv);
        this.e.setOnKeyListener(this);
        this.f.setOnKeyListener(this);
        this.g.setOnKeyListener(this);
        this.h.setOnKeyListener(this);
        this.n.setOnKeyListener(this);
        this.e.setOnFocusChangeListener(this);
        this.f.setOnFocusChangeListener(this);
        this.g.setOnFocusChangeListener(this);
        this.h.setOnFocusChangeListener(this);
        this.n.setOnFocusChangeListener(this);
        try {
            JSONObject jSONObjectK = this.j.k(this.a);
            this.k.setBackgroundColor(Color.parseColor(this.j.a()));
            this.l.setBackgroundColor(Color.parseColor(this.j.a()));
            this.r.setBackgroundColor(Color.parseColor(this.j.l()));
            this.i.setBackgroundColor(Color.parseColor((String) this.j.j.B.b));
            androidx.constraintlayout.motion.widget.n nVar = this.j.j.y;
            AbstractC3617f4.d(this.e, nVar);
            AbstractC3617f4.d(this.f, this.j.j.w);
            AbstractC3617f4.d(this.g, this.j.j.x);
            com.onetrust.otpublishers.headless.UI.Helper.c cVar = this.j.r;
            J(false, nVar);
            this.n.setVisibility(cVar.p);
            if (!com.onetrust.otpublishers.headless.Internal.a.j(cVar.a())) {
                this.h.setText(cVar.a());
                if (AbstractC3605e0.a((String) cVar.s.k)) {
                    AbstractC3617f4.d(this.h, cVar.s);
                } else {
                    String strB = cVar.b();
                    Button button = this.h;
                    if (!com.onetrust.otpublishers.headless.Internal.a.j(strB)) {
                        button.setTextColor(Color.parseColor(strB));
                    }
                    button.setPaintFlags(button.getPaintFlags() | 8);
                    button.getBackground().setTint(Color.parseColor(this.j.a()));
                    button.setElevation(DefinitionKt.NO_Float_VALUE);
                }
            }
            this.h.setVisibility(cVar.t);
            a();
            if (jSONObjectK != null) {
                JSONArray jSONArrayG = G(jSONObjectK.getJSONArray("Groups"));
                int i2 = (getArguments() == null || !getArguments().containsKey("OT_FOCUSED_PC_LIST_ITEM")) ? 0 : getArguments().getInt("OT_FOCUSED_PC_LIST_ITEM");
                com.onetrust.otpublishers.headless.UI.TVUI.adapter.i iVar = new com.onetrust.otpublishers.headless.UI.TVUI.adapter.i(this.a, jSONArrayG, this);
                this.s = iVar;
                iVar.d = i2;
                this.i.setAdapter(iVar);
                a(jSONArrayG.getJSONObject(0));
                return viewInflate;
            }
        } catch (IndexOutOfBoundsException e) {
            e = e;
            sb = new StringBuilder("error while populating PC list");
            sb.append(e.getMessage());
            OTLogger.c("TVPreferenceCenter", 6, sb.toString());
            return viewInflate;
        } catch (JSONException e2) {
            e = e2;
            sb = new StringBuilder("JSON error while populating PC fields");
            sb.append(e.getMessage());
            OTLogger.c("TVPreferenceCenter", 6, sb.toString());
            return viewInflate;
        }
        return viewInflate;
    }

    @Override // android.view.View.OnFocusChangeListener
    public final void onFocusChange(View view, boolean z) {
        if (view.getId() == R.id.tv_btn_confirm) {
            AbstractC3617f4.k(this.e, this.j.j.y, z);
        }
        if (view.getId() == R.id.tv_btn_reject_pc) {
            AbstractC3617f4.k(this.g, this.j.j.x, z);
        }
        if (view.getId() == R.id.tv_btn_accept_pc) {
            AbstractC3617f4.k(this.f, this.j.j.w, z);
        }
        if (view.getId() == R.id.ot_tv_pc_close_button) {
            androidx.constraintlayout.motion.widget.n nVar = this.j.r.s;
            if (AbstractC3605e0.a((String) nVar.k)) {
                AbstractC3617f4.k(this.h, nVar, z);
            } else {
                Button button = this.h;
                String strB = this.j.r.b();
                if (z) {
                    AbstractC3617f4.k(button, nVar, true);
                    button.setPaintFlags(button.getPaintFlags() & (-9));
                } else {
                    if (!com.onetrust.otpublishers.headless.Internal.a.j(strB)) {
                        button.setTextColor(Color.parseColor(strB));
                    }
                    button.setPaintFlags(button.getPaintFlags() | 8);
                    button.getBackground().setTint(Color.parseColor(this.j.a()));
                    button.setElevation(DefinitionKt.NO_Float_VALUE);
                }
            }
        }
        if (view.getId() == R.id.ot_tv_pc_close) {
            J(z, this.j.j.y);
        }
    }

    @Override // android.view.View.OnKeyListener
    public final boolean onKey(View view, int i, KeyEvent keyEvent) {
        TextView textView;
        View view2;
        TextView textView2;
        View view3;
        TextView textView3;
        View view4;
        TextView textView4;
        View view5;
        TextView textView5;
        View view6;
        if (view.getId() == R.id.tv_btn_confirm && AbstractC3617f4.a(i, keyEvent) == 21) {
            this.c.p(14);
        }
        if (view.getId() == R.id.tv_btn_confirm && AbstractC3617f4.a(i, keyEvent) == 25) {
            if (!this.t) {
                this.s.notifyDataSetChanged();
                return true;
            }
            i iVar = this.p;
            if (iVar != null) {
                CardView cardView = iVar.t;
                if (cardView == null || cardView.getVisibility() != 0) {
                    CardView cardView2 = iVar.u;
                    if (cardView2 == null || cardView2.getVisibility() != 0) {
                        view6 = iVar.b;
                        if (view6 != null) {
                        }
                    } else {
                        view6 = iVar.u;
                    }
                } else {
                    view6 = iVar.t;
                }
                view6.requestFocus();
            }
            c cVar = this.q;
            if (cVar != null && (textView5 = cVar.b) != null) {
                textView5.requestFocus();
            }
            d dVar = this.o;
            if (dVar.u.optBoolean("IS_PARTNERS_LINK")) {
                dVar.r.requestFocus();
                return true;
            }
            if (dVar.B.getVisibility() == 0) {
                dVar.B.requestFocus();
                return true;
            }
            if (dVar.C.getVisibility() == 0) {
                dVar.C.requestFocus();
                return true;
            }
            if (dVar.b.getVisibility() == 0) {
                dVar.b.requestFocus();
                return true;
            }
        } else if (view.getId() == R.id.tv_btn_accept_pc && AbstractC3617f4.a(i, keyEvent) == 25) {
            if (!this.t) {
                this.s.notifyDataSetChanged();
                return true;
            }
            i iVar2 = this.p;
            if (iVar2 != null) {
                CardView cardView3 = iVar2.t;
                if (cardView3 == null || cardView3.getVisibility() != 0) {
                    CardView cardView4 = iVar2.u;
                    if (cardView4 == null || cardView4.getVisibility() != 0) {
                        view5 = iVar2.b;
                        if (view5 != null) {
                        }
                    } else {
                        view5 = iVar2.u;
                    }
                } else {
                    view5 = iVar2.t;
                }
                view5.requestFocus();
            }
            c cVar2 = this.q;
            if (cVar2 != null && (textView4 = cVar2.b) != null) {
                textView4.requestFocus();
            }
            d dVar2 = this.o;
            if (dVar2.u.optBoolean("IS_PARTNERS_LINK")) {
                dVar2.r.requestFocus();
                return true;
            }
            if (dVar2.B.getVisibility() == 0) {
                dVar2.B.requestFocus();
                return true;
            }
            if (dVar2.C.getVisibility() == 0) {
                dVar2.C.requestFocus();
                return true;
            }
            if (dVar2.b.getVisibility() == 0) {
                dVar2.b.requestFocus();
                return true;
            }
        } else if (view.getId() != R.id.tv_btn_reject_pc || AbstractC3617f4.a(i, keyEvent) != 25) {
            if (view.getId() == R.id.tv_btn_accept_pc && AbstractC3617f4.a(i, keyEvent) == 21) {
                this.c.p(21);
            }
            if (view.getId() == R.id.tv_btn_reject_pc && AbstractC3617f4.a(i, keyEvent) == 21) {
                this.c.p(22);
            }
            if (i == 4 && keyEvent.getAction() == 1) {
                this.c.p(23);
            }
            if ((view.getId() == R.id.ot_tv_pc_close || view.getId() == R.id.ot_tv_pc_close_button) && AbstractC3617f4.a(i, keyEvent) == 21) {
                this.b.resetUpdatedConsent();
                this.c.p(23);
            }
            if ((view.getId() == R.id.ot_tv_pc_close || view.getId() == R.id.ot_tv_pc_close_button) && AbstractC3617f4.a(i, keyEvent) == 26) {
                if (!this.t) {
                    this.s.notifyDataSetChanged();
                    return true;
                }
                i iVar3 = this.p;
                if (iVar3 != null) {
                    CardView cardView5 = iVar3.t;
                    if (cardView5 == null || cardView5.getVisibility() != 0) {
                        CardView cardView6 = iVar3.u;
                        if (cardView6 == null || cardView6.getVisibility() != 0) {
                            view2 = iVar3.b;
                            if (view2 != null) {
                            }
                        } else {
                            view2 = iVar3.u;
                        }
                    } else {
                        view2 = iVar3.t;
                    }
                    view2.requestFocus();
                }
                c cVar3 = this.q;
                if (cVar3 != null && (textView = cVar3.b) != null) {
                    textView.requestFocus();
                }
                d dVar3 = this.o;
                if (dVar3.u.optBoolean("IS_PARTNERS_LINK")) {
                    dVar3.r.requestFocus();
                    return true;
                }
                if (dVar3.B.getVisibility() == 0) {
                    dVar3.B.requestFocus();
                    return true;
                }
                if (dVar3.C.getVisibility() == 0) {
                    dVar3.C.requestFocus();
                    return true;
                }
                if (dVar3.b.getVisibility() == 0) {
                    dVar3.b.requestFocus();
                    return true;
                }
            } else {
                if ((view.getId() != R.id.ot_tv_pc_close && view.getId() != R.id.ot_tv_pc_close_button) || AbstractC3617f4.a(i, keyEvent) != 24) {
                    return false;
                }
                i iVar4 = this.p;
                if (iVar4 != null) {
                    CardView cardView7 = iVar4.t;
                    if (cardView7 == null || cardView7.getVisibility() != 0) {
                        CardView cardView8 = iVar4.u;
                        if (cardView8 == null || cardView8.getVisibility() != 0) {
                            view3 = iVar4.b;
                            if (view3 != null) {
                            }
                        } else {
                            view3 = iVar4.u;
                        }
                    } else {
                        view3 = iVar4.t;
                    }
                    view3.requestFocus();
                }
                c cVar4 = this.q;
                if (cVar4 != null && (textView2 = cVar4.b) != null) {
                    textView2.requestFocus();
                }
                d dVar4 = this.o;
                if (dVar4.u.optBoolean("IS_PARTNERS_LINK")) {
                    dVar4.r.requestFocus();
                    return true;
                }
                if (dVar4.B.getVisibility() == 0) {
                    dVar4.B.requestFocus();
                    return true;
                }
                if (dVar4.C.getVisibility() == 0) {
                    dVar4.C.requestFocus();
                    return true;
                }
                if (dVar4.b.getVisibility() == 0) {
                    dVar4.b.requestFocus();
                }
            }
        } else {
            if (!this.t) {
                this.s.notifyDataSetChanged();
                return true;
            }
            i iVar5 = this.p;
            if (iVar5 != null) {
                CardView cardView9 = iVar5.t;
                if (cardView9 == null || cardView9.getVisibility() != 0) {
                    CardView cardView10 = iVar5.u;
                    if (cardView10 == null || cardView10.getVisibility() != 0) {
                        view4 = iVar5.b;
                        if (view4 != null) {
                        }
                    } else {
                        view4 = iVar5.u;
                    }
                } else {
                    view4 = iVar5.t;
                }
                view4.requestFocus();
            }
            c cVar5 = this.q;
            if (cVar5 != null && (textView3 = cVar5.b) != null) {
                textView3.requestFocus();
            }
            d dVar5 = this.o;
            if (dVar5.u.optBoolean("IS_PARTNERS_LINK")) {
                dVar5.r.requestFocus();
                return true;
            }
            if (dVar5.B.getVisibility() == 0) {
                dVar5.B.requestFocus();
                return true;
            }
            if (dVar5.C.getVisibility() == 0) {
                dVar5.C.requestFocus();
                return true;
            }
            if (dVar5.b.getVisibility() == 0) {
                dVar5.b.requestFocus();
                return true;
            }
        }
        return true;
    }

    public final void p(int i) {
        if (i == 24) {
            this.s.notifyDataSetChanged();
        }
        if (i == 26) {
            this.f.requestFocus();
        }
        if (18 == i) {
            this.c.p(18);
        }
        if (17 == i) {
            this.c.p(17);
        }
    }

    public final void a() {
        boolean z;
        com.onetrust.otpublishers.headless.Internal.Preferences.f fVar;
        com.onetrust.otpublishers.headless.Internal.Preferences.f fVar2;
        if (!this.j.j.A.i()) {
            RelativeLayout.LayoutParams layoutParams = new RelativeLayout.LayoutParams(-2, -2);
            layoutParams.topMargin = getResources().getDimensionPixelSize(R.dimen.ot_sdk_search_margin);
            this.m.setLayoutParams(layoutParams);
            return;
        }
        I i = this.a;
        SharedPreferences sharedPreferences = i.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
        boolean z2 = true;
        String proxyDomainURLString = null;
        if (new com.onetrust.otpublishers.headless.Internal.profile.c(i).t()) {
            fVar = new com.onetrust.otpublishers.headless.Internal.Preferences.f(i, sharedPreferences, sharedPreferences.getString("OT_ACTIVE_PROFILE_ID", ""));
            z = true;
        } else {
            z = false;
            fVar = null;
        }
        if (z) {
            sharedPreferences = fVar;
        }
        if (sharedPreferences.getBoolean("OTT_LOAD_OFFLINE_DATA", false)) {
            OTConfiguration oTConfiguration = this.u;
            if (oTConfiguration == null || oTConfiguration.getPcLogo() == null) {
                return;
            }
        } else {
            I i2 = this.a;
            SharedPreferences sharedPreferences2 = i2.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
            if (new com.onetrust.otpublishers.headless.Internal.profile.c(i2).t()) {
                fVar2 = new com.onetrust.otpublishers.headless.Internal.Preferences.f(i2, sharedPreferences2, sharedPreferences2.getString("OT_ACTIVE_PROFILE_ID", ""));
            } else {
                z2 = false;
                fVar2 = null;
            }
            if (z2) {
                sharedPreferences2 = fVar2;
            }
            if (!sharedPreferences2.getBoolean("OTT_OFFLINE_DATA_SET_FLAG", false) || AbstractC3581b0.d(this.a)) {
                String strH = this.j.j.A.h();
                try {
                    proxyDomainURLString = OTCustomConfigurator.getProxyDomainURLString(new OTProxyType.PCLogo(new URL(strH)));
                } catch (MalformedURLException e) {
                    OTLogger.c("TVPreferenceCenter", 6, "Error while fetching PC Logo using proxy" + e.getMessage());
                }
                AbstractC3649j4.a(R.drawable.ic_ot, this.m, proxyDomainURLString, strH, "Preference Center");
                return;
            }
            OTConfiguration oTConfiguration2 = this.u;
            if (oTConfiguration2 == null || oTConfiguration2.getPcLogo() == null) {
                return;
            }
        }
        this.m.setImageDrawable(this.u.getPcLogo());
    }
}

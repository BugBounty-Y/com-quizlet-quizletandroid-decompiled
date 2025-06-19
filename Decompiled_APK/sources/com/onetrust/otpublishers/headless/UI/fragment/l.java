package com.onetrust.otpublishers.headless.UI.fragment;

import android.app.Dialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.res.Configuration;
import android.content.res.Resources;
import android.graphics.Color;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.TextView;
import android.widget.Toast;
import androidx.core.view.V;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3206m6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3581b0;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3605e0;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3617f4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3649j4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3705q4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.K;
import com.google.android.gms.internal.mlkit_vision_document_scanner.P;
import com.google.android.gms.internal.mlkit_vision_document_scanner.Q;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.onetrust.otpublishers.headless.Public.DataModel.OTConfiguration;
import com.onetrust.otpublishers.headless.Public.DataModel.OTCustomConfigurator;
import com.onetrust.otpublishers.headless.Public.DataModel.OTProxyType;
import com.onetrust.otpublishers.headless.Public.Keys.OTFragmentTags;
import com.onetrust.otpublishers.headless.Public.OTConsentInteractionType;
import com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK;
import com.onetrust.otpublishers.headless.Public.OTThemeConstants;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;
import kotlin.Pair;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public class l extends com.google.android.material.bottomsheet.i implements View.OnClickListener, com.onetrust.otpublishers.headless.UI.a, com.onetrust.otpublishers.headless.UI.adapter.t {
    public RecyclerView A;
    public Button B;
    public Button C;
    public Button D;
    public com.google.android.material.bottomsheet.h E;
    public ImageView F;
    public ImageView G;
    public ImageView H;
    public TextView I;
    public Button J;
    public RelativeLayout K;
    public Context L;
    public LinearLayout M;
    public LinearLayout V;
    public OTPublishersHeadlessSDK W;
    public D X;
    public s Y;
    public C4063g Z;
    public OTConfiguration d1;
    public assistantMode.utils.studiableMetadata.b e1;
    public androidx.room.s f1;
    public View g1;
    public View h1;
    public View i1;
    public View j1;
    public View k1;
    public View l1;
    public TextView m1;
    public com.onetrust.otpublishers.headless.UI.mobiledatautils.b n1;
    public TextView o1;
    public TextView p1;
    public TextView q;
    public View q1;
    public TextView r;
    public View r1;
    public TextView s;
    public int s1;
    public TextView t;
    public boolean t1;
    public TextView u;
    public TextView v;
    public TextView w;
    public TextView x;
    public TextView y;
    public TextView z;
    public com.onetrust.otpublishers.headless.Internal.Event.a c1 = new com.onetrust.otpublishers.headless.Internal.Event.a();
    public boolean u1 = true;

    @Override // com.google.android.material.bottomsheet.i, androidx.appcompat.app.E, androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t
    public final Dialog K(Bundle bundle) {
        Dialog dialogK = super.K(bundle);
        dialogK.setOnShowListener(new com.onetrust.otpublishers.headless.UI.TVUI.fragments.e(this, 6));
        return dialogK;
    }

    public final void Q(int i, boolean z) {
        G();
        C4063g c4063g = this.Z;
        if (c4063g != null) {
            c4063g.p(i);
            return;
        }
        if (z) {
            androidx.compose.foundation.lazy.grid.m mVar = new androidx.compose.foundation.lazy.grid.m(17, 4);
            mVar.d = OTConsentInteractionType.PC_CLOSE;
            assistantMode.utils.studiableMetadata.b bVar = this.e1;
            com.onetrust.otpublishers.headless.Internal.Event.a aVar = this.c1;
            bVar.getClass();
            assistantMode.utils.studiableMetadata.b.y(mVar, aVar);
        }
    }

    public final void R(androidx.constraintlayout.motion.widget.n nVar, androidx.constraintlayout.motion.widget.n nVar2, androidx.constraintlayout.motion.widget.n nVar3) {
        LinearLayout linearLayout;
        Object value;
        int i = nVar.c;
        int i2 = nVar2.c;
        int i3 = nVar3.c;
        if (i == 0 && i2 == 0 && i3 == 0) {
            OTLogger.c("PreferenceCenter", 3, "Reordering PC buttons not required");
            return;
        }
        try {
            OTLogger.c("PreferenceCenter", 3, "Reordering PC buttons as per admin configuration");
            HashMap map = new HashMap();
            map.put(Integer.valueOf(i), this.B);
            map.put(Integer.valueOf(i2), this.D);
            map.put(Integer.valueOf(i3), this.C);
            TreeMap treeMap = new TreeMap(map);
            this.V.removeAllViews();
            this.M.removeAllViews();
            for (Map.Entry entry : treeMap.entrySet()) {
                if (((Integer) entry.getKey()).intValue() < 10) {
                    linearLayout = this.V;
                    value = entry.getValue();
                } else {
                    linearLayout = this.M;
                    value = entry.getValue();
                }
                linearLayout.addView((View) value);
            }
            if (i > 10 || i2 > 10 || i3 > 10) {
                return;
            }
            this.M.setVisibility(4);
            this.M.setElevation(DefinitionKt.NO_Float_VALUE);
            this.M.setBackgroundColor(0);
            this.M.setPaddingRelative(0, 0, 0, 0);
        } catch (Exception e) {
            OTLogger.c("PreferenceCenter", 6, "Reordering PC buttons failed, falling back to default:" + e);
            this.V.removeAllViews();
            this.M.removeAllViews();
            this.V.addView(this.B);
            this.V.addView(this.D);
            this.M.addView(this.C);
            this.M.setVisibility(0);
        }
    }

    public final void S(com.onetrust.otpublishers.headless.UI.Helper.c cVar, Button button) {
        button.setText(cVar.a());
        button.setVisibility(cVar.p);
        button.setTextColor(Color.parseColor(cVar.b()));
        if (!com.onetrust.otpublishers.headless.Internal.a.j((String) ((com.google.android.gms.cloudmessaging.k) cVar.d).d)) {
            button.setTextSize(Float.parseFloat(cVar.r));
        }
        assistantMode.utils.studiableMetadata.b bVar = this.e1;
        com.google.android.gms.cloudmessaging.k kVar = (com.google.android.gms.cloudmessaging.k) cVar.d;
        OTConfiguration oTConfiguration = this.d1;
        bVar.getClass();
        assistantMode.utils.studiableMetadata.b.u(button, kVar, oTConfiguration);
        assistantMode.utils.studiableMetadata.b.q(this.L, button, cVar.s, (String) cVar.e, (String) cVar.g);
    }

    public final void T(com.onetrust.otpublishers.headless.UI.Helper.c cVar, ImageView imageView, TextView textView, Button button) {
        imageView.setVisibility(cVar.p);
        imageView.setContentDescription(cVar.a());
        textView.setVisibility(cVar.t);
        imageView.getDrawable().setTint(Color.parseColor(cVar.b()));
        int i = 0;
        if (cVar.u == 0) {
            button.setVisibility(0);
            button.setText(cVar.a());
            button.setTextColor(Color.parseColor(cVar.b()));
            if (!com.onetrust.otpublishers.headless.Internal.a.j((String) ((com.google.android.gms.cloudmessaging.k) cVar.d).d)) {
                button.setTextSize(Float.parseFloat(cVar.r));
            }
            assistantMode.utils.studiableMetadata.b bVar = this.e1;
            com.google.android.gms.cloudmessaging.k kVar = (com.google.android.gms.cloudmessaging.k) cVar.d;
            OTConfiguration oTConfiguration = this.d1;
            bVar.getClass();
            assistantMode.utils.studiableMetadata.b.u(button, kVar, oTConfiguration);
            assistantMode.utils.studiableMetadata.b.q(this.L, button, cVar.s, (String) cVar.e, (String) cVar.g);
        } else if (cVar.t == 0) {
            textView.setText(cVar.a());
            textView.setTextColor(Color.parseColor(cVar.b()));
            androidx.room.s sVar = this.f1;
            if (sVar == null || sVar.c) {
                textView.setPaintFlags(textView.getPaintFlags() | 8);
            }
        }
        View view = this.k1;
        if (cVar.t == 8 && cVar.p == 8 && cVar.u == 8) {
            i = 8;
        }
        view.setVisibility(i);
    }

    public final void U(com.onetrust.otpublishers.headless.UI.Helper.c cVar, TextView textView) throws NumberFormatException {
        assistantMode.utils.studiableMetadata.b bVar = this.e1;
        Context context = this.L;
        String strA = cVar.a();
        bVar.getClass();
        assistantMode.utils.studiableMetadata.b.r(context, textView, strA);
        textView.setVisibility(cVar.p);
        textView.setTextColor(Color.parseColor(cVar.b()));
        assistantMode.utils.studiableMetadata.b.x(textView, cVar.q);
        if (!com.onetrust.otpublishers.headless.Internal.a.j(cVar.r)) {
            textView.setTextSize(Float.parseFloat(cVar.r));
        }
        assistantMode.utils.studiableMetadata.b bVar2 = this.e1;
        com.google.android.gms.cloudmessaging.k kVar = (com.google.android.gms.cloudmessaging.k) cVar.d;
        OTConfiguration oTConfiguration = this.d1;
        bVar2.getClass();
        assistantMode.utils.studiableMetadata.b.w(textView, kVar, oTConfiguration);
    }

    public final void V(com.onetrust.otpublishers.headless.UI.mobiledatautils.b bVar, TextView textView) {
        androidx.navigation.internal.m mVar;
        com.onetrust.otpublishers.headless.UI.Helper.c cVar;
        if (textView.equals(this.v)) {
            String str = bVar.z;
            String str2 = (String) bVar.u.m.g;
            if ("true".equals(str) || !com.onetrust.otpublishers.headless.Internal.a.j(str2)) {
                textView.setVisibility(0);
            } else {
                textView.setVisibility(8);
            }
            textView.setText((String) bVar.B.g);
            com.onetrust.otpublishers.headless.UI.mobiledatautils.b.b(textView, bVar.B, bVar.j, this.d1);
            ImageView imageView = this.H;
            String str3 = bVar.u.G.b;
            if (str3 == null) {
                str3 = "";
            }
            imageView.setContentDescription(str3);
            return;
        }
        if (textView.equals(this.z)) {
            String str4 = bVar.A;
            String str5 = (String) bVar.u.r.g;
            if ("true".equals(str4) || !com.onetrust.otpublishers.headless.Internal.a.j(str5)) {
                textView.setVisibility(0);
            } else {
                textView.setVisibility(8);
            }
            assistantMode.utils.studiableMetadata.b bVar2 = this.e1;
            Context context = this.L;
            String str6 = (String) bVar.C.g;
            bVar2.getClass();
            assistantMode.utils.studiableMetadata.b.r(context, textView, str6);
            mVar = bVar.C;
            cVar = bVar.b;
        } else {
            if (textView.equals(this.w)) {
                textView.setText((String) bVar.D.g);
                mVar = bVar.D;
            } else if (textView.equals(this.y)) {
                textView.setText((String) bVar.F.g);
                mVar = bVar.F;
                cVar = bVar.j;
            } else {
                if (!textView.equals(this.x)) {
                    return;
                }
                textView.setText((String) bVar.E.g);
                mVar = bVar.E;
            }
            cVar = bVar.x;
        }
        OTConfiguration oTConfiguration = this.d1;
        bVar.getClass();
        com.onetrust.otpublishers.headless.UI.mobiledatautils.b.b(textView, mVar, cVar, oTConfiguration);
    }

    public final void W() throws Resources.NotFoundException {
        boolean z;
        com.onetrust.otpublishers.headless.Internal.Preferences.f fVar;
        com.onetrust.otpublishers.headless.Internal.Preferences.f fVar2;
        String str;
        com.onetrust.otpublishers.headless.UI.Helper.c cVar = this.n1.i;
        this.G.setVisibility(cVar.p);
        ImageView imageView = this.G;
        String str2 = (String) this.n1.u.A.d;
        if (str2 == null) {
            str2 = "";
        }
        imageView.setContentDescription(str2);
        if (cVar.p == 0) {
            boolean z2 = true;
            int i = assistantMode.utils.studiableMetadata.b.i(requireActivity(), true);
            int i2 = assistantMode.utils.studiableMetadata.b.i(requireActivity(), false) / 2;
            int i3 = i / 9;
            int dimensionPixelSize = getResources().getDimensionPixelSize(R.dimen.ot_margin_very_small);
            RelativeLayout.LayoutParams layoutParams = new RelativeLayout.LayoutParams(i2, i3);
            layoutParams.addRule(14);
            layoutParams.setMargins(0, dimensionPixelSize, 0, 0);
            this.G.setLayoutParams(layoutParams);
            if (P.k(this.L)) {
                RelativeLayout.LayoutParams layoutParams2 = new RelativeLayout.LayoutParams(i2, i3);
                layoutParams2.addRule(18);
                layoutParams2.setMargins(0, dimensionPixelSize, getResources().getDimensionPixelSize(R.dimen.ot_logo_margin), 0);
                this.G.setLayoutParams(layoutParams2);
            }
            Context context = this.L;
            SharedPreferences sharedPreferences = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
            String proxyDomainURLString = null;
            if (Q.a(context)) {
                fVar = new com.onetrust.otpublishers.headless.Internal.Preferences.f(context, sharedPreferences, sharedPreferences.getString("OT_ACTIVE_PROFILE_ID", ""));
                z = true;
            } else {
                z = false;
                fVar = null;
            }
            if (z) {
                sharedPreferences = fVar;
            }
            if (sharedPreferences.getBoolean("OTT_LOAD_OFFLINE_DATA", false)) {
                OTConfiguration oTConfiguration = this.d1;
                if (oTConfiguration == null || oTConfiguration.getPcLogo() == null) {
                    return;
                } else {
                    str = "Loading offline logo for PC.";
                }
            } else {
                Context context2 = this.L;
                SharedPreferences sharedPreferences2 = context2.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
                if (Q.a(context2)) {
                    fVar2 = new com.onetrust.otpublishers.headless.Internal.Preferences.f(context2, sharedPreferences2, sharedPreferences2.getString("OT_ACTIVE_PROFILE_ID", ""));
                } else {
                    z2 = false;
                    fVar2 = null;
                }
                if (z2) {
                    sharedPreferences2 = fVar2;
                }
                if (!sharedPreferences2.getBoolean("OTT_OFFLINE_DATA_SET_FLAG", false) || AbstractC3581b0.d(this.L)) {
                    String strA = cVar.a();
                    try {
                        proxyDomainURLString = OTCustomConfigurator.getProxyDomainURLString(new OTProxyType.PCLogo(new URL(strA)));
                    } catch (MalformedURLException e) {
                        OTLogger.c("PreferenceCenter", 6, "Error while fetching PC Logo using proxy" + e.getMessage());
                    }
                    AbstractC3649j4.a(R.drawable.ic_ot, this.G, proxyDomainURLString, strA, "Preference Center");
                    return;
                }
                OTConfiguration oTConfiguration2 = this.d1;
                if (oTConfiguration2 == null || oTConfiguration2.getPcLogo() == null) {
                    return;
                } else {
                    str = "Loading offline set logo for PC.";
                }
            }
            OTLogger.c("PreferenceCenter", 3, str);
            this.G.setImageDrawable(this.d1.getPcLogo());
        }
    }

    public final void X() {
        com.onetrust.otpublishers.headless.UI.mobiledatautils.b bVar = this.n1;
        if (bVar.z != null) {
            V(bVar, this.v);
            com.onetrust.otpublishers.headless.UI.mobiledatautils.b bVar2 = this.n1;
            if (bVar2.A != null) {
                V(bVar2, this.z);
            } else {
                this.z.setVisibility(8);
            }
            V(this.n1, this.w);
        } else {
            this.v.setVisibility(8);
            this.w.setVisibility(8);
            this.z.setVisibility(8);
            this.H.setVisibility(8);
            this.l1.setVisibility(8);
        }
        if ("true".equals(this.n1.G)) {
            V(this.n1, this.y);
            V(this.n1, this.x);
        } else {
            this.y.setVisibility(8);
            this.x.setVisibility(8);
        }
    }

    public final void Y() {
        String str = this.n1.t;
        K.c("setSectionDividerColor PC: ", 3, str, "OT_Automation");
        com.google.mlkit.common.internal.model.a.i(this.g1, str);
        com.google.mlkit.common.internal.model.a.i(this.h1, str);
        com.google.mlkit.common.internal.model.a.i(this.q1, str);
        com.google.mlkit.common.internal.model.a.i(this.r1, str);
        com.google.mlkit.common.internal.model.a.i(this.i1, str);
        com.google.mlkit.common.internal.model.a.i(this.j1, str);
        com.google.mlkit.common.internal.model.a.i(this.l1, str);
    }

    @Override // com.onetrust.otpublishers.headless.UI.adapter.t
    public final void a() {
        if (this.A.getAdapter() != null) {
            com.onetrust.otpublishers.headless.UI.adapter.m mVar = (com.onetrust.otpublishers.headless.UI.adapter.m) this.A.getAdapter();
            com.onetrust.otpublishers.headless.UI.mobiledatautils.b bVar = mVar.l;
            JSONArray jSONArray = bVar.p;
            mVar.d = jSONArray;
            mVar.h = bVar.u;
            mVar.notifyItemRangeChanged(0, jSONArray.length());
        }
    }

    public final void a0() {
        if (!this.t1) {
            this.r1.setVisibility(8);
        }
        if (this.o1.getVisibility() == 8) {
            this.q1.setVisibility(8);
        }
        if (!this.n1.K || !this.u1) {
            this.r1.setVisibility(8);
            if (!this.t1) {
                this.o1.setVisibility(8);
                this.q1.setVisibility(8);
                this.i1.setVisibility(8);
            }
        }
        if (this.n1.p.length() > 0) {
            return;
        }
        this.p1.setVisibility(8);
    }

    @Override // android.view.View.OnClickListener
    public final void onClick(View view) throws JSONException {
        int id = view.getId();
        if (id == R.id.btn_allow_all) {
            this.W.saveConsent(OTConsentInteractionType.PC_ALLOW_ALL);
            assistantMode.utils.studiableMetadata.b bVar = this.e1;
            androidx.compose.foundation.lazy.grid.m mVar = new androidx.compose.foundation.lazy.grid.m(8, 4);
            com.onetrust.otpublishers.headless.Internal.Event.a aVar = this.c1;
            bVar.getClass();
            assistantMode.utils.studiableMetadata.b.y(mVar, aVar);
            androidx.compose.foundation.lazy.grid.m mVar2 = new androidx.compose.foundation.lazy.grid.m(17, 4);
            mVar2.d = OTConsentInteractionType.PC_ALLOW_ALL;
            assistantMode.utils.studiableMetadata.b bVar2 = this.e1;
            com.onetrust.otpublishers.headless.Internal.Event.a aVar2 = this.c1;
            bVar2.getClass();
            assistantMode.utils.studiableMetadata.b.y(mVar2, aVar2);
        } else if (id == R.id.btn_confirm_choices) {
            this.W.saveConsent(OTConsentInteractionType.PC_CONFIRM);
            assistantMode.utils.studiableMetadata.b bVar3 = this.e1;
            androidx.compose.foundation.lazy.grid.m mVar3 = new androidx.compose.foundation.lazy.grid.m(10, 4);
            com.onetrust.otpublishers.headless.Internal.Event.a aVar3 = this.c1;
            bVar3.getClass();
            assistantMode.utils.studiableMetadata.b.y(mVar3, aVar3);
            androidx.compose.foundation.lazy.grid.m mVar4 = new androidx.compose.foundation.lazy.grid.m(17, 4);
            mVar4.d = OTConsentInteractionType.PC_CONFIRM;
            assistantMode.utils.studiableMetadata.b bVar4 = this.e1;
            com.onetrust.otpublishers.headless.Internal.Event.a aVar4 = this.c1;
            bVar4.getClass();
            assistantMode.utils.studiableMetadata.b.y(mVar4, aVar4);
        } else {
            if (id == R.id.close_pc || id == R.id.close_pc_text || id == R.id.close_pc_button) {
                this.W.resetUpdatedConsent();
                assistantMode.utils.studiableMetadata.b bVar5 = this.e1;
                androidx.compose.foundation.lazy.grid.m mVar5 = new androidx.compose.foundation.lazy.grid.m(6, 4);
                com.onetrust.otpublishers.headless.Internal.Event.a aVar5 = this.c1;
                bVar5.getClass();
                assistantMode.utils.studiableMetadata.b.y(mVar5, aVar5);
                Q(2, true);
                return;
            }
            if (id != R.id.btn_reject_PC) {
                if (id == R.id.view_all_vendors) {
                    if (this.X.isAdded() || getActivity() == null) {
                        OTLogger.c("PreferenceCenter", 6, "Show Vendors: Fragment already added or getActivity() returned null");
                        return;
                    }
                    Bundle bundle = new Bundle();
                    bundle.putBoolean("IS_FILTERED_VENDOR_LIST", false);
                    this.X.setArguments(bundle);
                    D d = this.X;
                    d.v = this;
                    com.google.mlkit.common.internal.model.a.o(d, requireActivity(), OTFragmentTags.OT_VENDOR_LIST_FRAGMENT_TAG);
                    assistantMode.utils.studiableMetadata.b bVar6 = this.e1;
                    androidx.compose.foundation.lazy.grid.m mVar6 = new androidx.compose.foundation.lazy.grid.m(12, 4);
                    com.onetrust.otpublishers.headless.Internal.Event.a aVar6 = this.c1;
                    bVar6.getClass();
                    assistantMode.utils.studiableMetadata.b.y(mVar6, aVar6);
                    return;
                }
                if (id == R.id.cookie_policy_link) {
                    com.onetrust.otpublishers.headless.Internal.a.c(this.L, this.n1.q);
                    return;
                }
                if (id == R.id.text_copy) {
                    Context context = this.L;
                    ((ClipboardManager) context.getSystemService("clipboard")).setPrimaryClip(ClipData.newPlainText("copiedText", this.w.getText().toString()));
                    Toast.makeText(context, "Data Copied to Clipboard", 0).show();
                    return;
                }
                if (id == R.id.view_all_sdks) {
                    if (this.Y.isAdded() || getActivity() == null) {
                        OTLogger.c("PreferenceCenter", 6, "renderSDKListFragment: Fragment already added or getActivity() returned null");
                        return;
                    }
                    Bundle bundle2 = new Bundle();
                    androidx.work.impl.model.l lVar = new androidx.work.impl.model.l(14);
                    lVar.g(this.s1, this.L, this.W);
                    if (androidx.work.impl.model.l.f(P.g((JSONObject) lVar.c)).isEmpty()) {
                        this.u1 = false;
                    }
                    bundle2.putString("OT_GROUP_ID_LIST", androidx.work.impl.model.l.f(P.g((JSONObject) lVar.c)).toString());
                    bundle2.putString("sdkLevelOptOutShow", this.n1.H);
                    com.onetrust.otpublishers.headless.UI.Helper.c cVar = this.n1.w;
                    bundle2.putString("ALWAYS_ACTIVE_TEXT", cVar.a());
                    bundle2.putString("ALWAYS_ACTIVE_TEXT_COLOR", cVar.b());
                    this.Y.setArguments(bundle2);
                    com.google.mlkit.common.internal.model.a.o(this.Y, requireActivity(), OTFragmentTags.OT_SDK_LIST_FRAGMENT_TAG);
                    return;
                }
                return;
            }
            this.W.saveConsent(OTConsentInteractionType.PC_REJECT_ALL);
            assistantMode.utils.studiableMetadata.b bVar7 = this.e1;
            androidx.compose.foundation.lazy.grid.m mVar7 = new androidx.compose.foundation.lazy.grid.m(9, 4);
            com.onetrust.otpublishers.headless.Internal.Event.a aVar7 = this.c1;
            bVar7.getClass();
            assistantMode.utils.studiableMetadata.b.y(mVar7, aVar7);
            androidx.compose.foundation.lazy.grid.m mVar8 = new androidx.compose.foundation.lazy.grid.m(17, 4);
            mVar8.d = OTConsentInteractionType.PC_REJECT_ALL;
            assistantMode.utils.studiableMetadata.b bVar8 = this.e1;
            com.onetrust.otpublishers.headless.Internal.Event.a aVar8 = this.c1;
            bVar8.getClass();
            assistantMode.utils.studiableMetadata.b.y(mVar8, aVar8);
        }
        Q(1, false);
    }

    @Override // androidx.fragment.app.Fragment, android.content.ComponentCallbacks
    public final void onConfigurationChanged(Configuration configuration) {
        super.onConfigurationChanged(configuration);
        assistantMode.utils.studiableMetadata.b bVar = this.e1;
        androidx.fragment.app.I activity = getActivity();
        com.google.android.material.bottomsheet.h hVar = this.E;
        bVar.getClass();
        assistantMode.utils.studiableMetadata.b.z(activity, hVar);
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, androidx.fragment.app.Fragment
    public final void onCreate(Bundle bundle) {
        Context applicationContext;
        super.onCreate(bundle);
        setRetainInstance(true);
        if (com.google.mlkit.common.internal.model.a.n(getContext(), OTFragmentTags.OT_PREFERENCE_CENTER_FRAGMENT_TAG) && (applicationContext = requireContext().getApplicationContext()) != null && this.W == null) {
            this.W = new OTPublishersHeadlessSDK(applicationContext);
        }
        androidx.fragment.app.I activity = getActivity();
        if (com.google.mlkit.common.internal.model.a.n(activity, OTFragmentTags.OT_PREFERENCE_CENTER_FRAGMENT_TAG)) {
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

    @Override // androidx.fragment.app.Fragment
    public final View onCreateView(LayoutInflater layoutInflater, ViewGroup viewGroup, Bundle bundle) {
        RuntimeException runtimeException;
        com.onetrust.otpublishers.headless.Internal.Preferences.f fVar;
        boolean z;
        com.onetrust.otpublishers.headless.UI.Helper.c cVar;
        this.L = getContext();
        com.google.firebase.perf.logging.b bVar = D.D;
        com.onetrust.otpublishers.headless.Internal.Event.a aVar = this.c1;
        OTConfiguration oTConfiguration = this.d1;
        bVar.getClass();
        D dA = com.google.firebase.perf.logging.b.a(aVar, oTConfiguration);
        this.X = dA;
        dA.R(this.W);
        OTConfiguration oTConfiguration2 = this.d1;
        Intrinsics.checkNotNullParameter(OTFragmentTags.OT_SDK_LIST_FRAGMENT_TAG, "fragmentTag");
        Bundle bundleA = AbstractC3206m6.a(new Pair(OTFragmentTags.FRAGMENT_TAG, OTFragmentTags.OT_SDK_LIST_FRAGMENT_TAG));
        s sVar = new s();
        sVar.setArguments(bundleA);
        sVar.t = oTConfiguration2;
        this.Y = sVar;
        Intrinsics.checkNotNullParameter(this, "listener");
        sVar.v = this;
        s sVar2 = this.Y;
        OTPublishersHeadlessSDK otPublishersHeadlessSDK = this.W;
        sVar2.getClass();
        Intrinsics.checkNotNullParameter(otPublishersHeadlessSDK, "otPublishersHeadlessSDK");
        sVar2.s = otPublishersHeadlessSDK;
        this.e1 = new assistantMode.utils.studiableMetadata.b(22);
        View viewJ = assistantMode.utils.studiableMetadata.b.j(this.L, layoutInflater, viewGroup, R.layout.fragment_ot_pc);
        RecyclerView recyclerView = (RecyclerView) viewJ.findViewById(R.id.preferences_list);
        this.A = recyclerView;
        recyclerView.setHasFixedSize(true);
        this.A.setLayoutManager(new LinearLayoutManager(getActivity()));
        this.A.setNestedScrollingEnabled(false);
        this.K = (RelativeLayout) viewJ.findViewById(R.id.pc_layout);
        this.M = (LinearLayout) viewJ.findViewById(R.id.footer_layout);
        this.V = (LinearLayout) viewJ.findViewById(R.id.allow_all_layout);
        this.r = (TextView) viewJ.findViewById(R.id.main_text);
        this.s = (TextView) viewJ.findViewById(R.id.preferences_header);
        this.C = (Button) viewJ.findViewById(R.id.btn_confirm_choices);
        this.q = (TextView) viewJ.findViewById(R.id.main_info_text);
        this.F = (ImageView) viewJ.findViewById(R.id.close_pc);
        this.I = (TextView) viewJ.findViewById(R.id.close_pc_text);
        this.J = (Button) viewJ.findViewById(R.id.close_pc_button);
        this.o1 = (TextView) viewJ.findViewById(R.id.ot_pc_vendor_sdk_list_section_header);
        this.p1 = (TextView) viewJ.findViewById(R.id.view_all_sdks);
        this.q1 = viewJ.findViewById(R.id.ot_pc_vendor_sdk_list_header_line_break);
        this.r1 = viewJ.findViewById(R.id.ot_pc_vendor_list_line_break);
        this.t = (TextView) viewJ.findViewById(R.id.view_all_vendors);
        this.D = (Button) viewJ.findViewById(R.id.btn_reject_PC);
        this.B = (Button) viewJ.findViewById(R.id.btn_allow_all);
        this.u = (TextView) viewJ.findViewById(R.id.cookie_policy_link);
        this.G = (ImageView) viewJ.findViewById(R.id.pc_logo);
        this.H = (ImageView) viewJ.findViewById(R.id.text_copy);
        this.g1 = viewJ.findViewById(R.id.ot_pc_vendor_sdk_list_section_divider);
        this.l1 = viewJ.findViewById(R.id.dsId_divider);
        this.h1 = viewJ.findViewById(R.id.ot_pc_allow_all_layout_top_divider);
        this.i1 = viewJ.findViewById(R.id.ot_pc_preferences_header_top_divider);
        this.j1 = viewJ.findViewById(R.id.ot_pc_preferences_list_top_divider);
        this.k1 = viewJ.findViewById(R.id.pc_title_divider);
        this.v = (TextView) viewJ.findViewById(R.id.dsid_title);
        this.w = (TextView) viewJ.findViewById(R.id.dsid);
        this.x = (TextView) viewJ.findViewById(R.id.time_stamp);
        this.y = (TextView) viewJ.findViewById(R.id.time_stamp_title);
        this.z = (TextView) viewJ.findViewById(R.id.dsid_description);
        this.m1 = (TextView) viewJ.findViewById(R.id.view_powered_by_logo);
        assistantMode.utils.studiableMetadata.b bVar2 = this.e1;
        LinearLayout linearLayout = this.M;
        Context context = this.L;
        bVar2.getClass();
        assistantMode.utils.studiableMetadata.b.t(linearLayout, context);
        this.B.setOnClickListener(this);
        this.F.setOnClickListener(this);
        this.I.setOnClickListener(this);
        this.J.setOnClickListener(this);
        this.C.setOnClickListener(this);
        this.D.setOnClickListener(this);
        this.u.setOnClickListener(this);
        this.t.setOnClickListener(this);
        this.p1.setOnClickListener(this);
        this.H.setOnClickListener(this);
        this.n1 = new com.onetrust.otpublishers.headless.UI.mobiledatautils.b();
        if (com.google.mlkit.common.internal.model.a.n(this.L, OTFragmentTags.OT_PREFERENCE_CENTER_FRAGMENT_TAG)) {
            com.google.mlkit.common.internal.model.a.f(this.L, viewJ, "PreferenceCenter");
            int iD = assistantMode.utils.studiableMetadata.b.d(this.L, this.d1);
            this.s1 = iD;
            if (!this.n1.j(iD, this.L, this.W)) {
                G();
            }
            this.f1 = this.n1.v;
            try {
                new androidx.work.impl.model.l(14).g(this.s1, this.L, this.W);
                this.u1 = !androidx.work.impl.model.l.f(P.g((JSONObject) r2.c)).isEmpty();
                Context context2 = this.L;
                SharedPreferences sharedPreferences = context2.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
                String str = "";
                if (AbstractC3605e0.a(context2.getSharedPreferences("com.onetrust.otpublishers.headless.preference".concat("OTT_DEFAULT_USER"), 0).getString("OT_ENABLE_MULTI_PROFILE", Boolean.FALSE.toString()))) {
                    try {
                        fVar = new com.onetrust.otpublishers.headless.Internal.Preferences.f(context2, sharedPreferences, sharedPreferences.getString("OT_ACTIVE_PROFILE_ID", ""));
                        z = true;
                    } catch (RuntimeException e) {
                        runtimeException = e;
                        OTLogger.c("PreferenceCenter", 6, "error while populating  PC fields" + runtimeException.getMessage());
                        return viewJ;
                    }
                } else {
                    fVar = null;
                    z = false;
                }
                if (z) {
                    sharedPreferences = fVar;
                }
                String string = sharedPreferences.getString("OT_TEMPLATE_TYPE", "");
                if (!com.onetrust.otpublishers.headless.Internal.a.j(string)) {
                    str = string;
                }
                this.t1 = "IAB2".equalsIgnoreCase(str) || "IAB2V2".equalsIgnoreCase(str);
                U(this.n1.a, this.r);
                V.p(this.r, true);
                U(this.n1.b, this.q);
                U(this.n1.e, this.u);
                com.google.mlkit.common.internal.model.a.k(this.u, this.n1.u.D.d());
                TextView textView = this.u;
                androidx.room.s sVar3 = this.f1;
                if (sVar3 == null || sVar3.c) {
                    textView.setPaintFlags(textView.getPaintFlags() | 8);
                }
                U(this.n1.f, this.o1);
                V.p(this.o1, true);
                U(this.n1.g, this.t);
                U(this.n1.h, this.p1);
                String str2 = this.n1.s;
                if (!com.onetrust.otpublishers.headless.Internal.a.j(str2)) {
                    AbstractC3617f4.f(this.t, str2);
                    AbstractC3617f4.f(this.p1, str2);
                    this.H.getDrawable().setTint(Color.parseColor(str2));
                }
                W();
                cVar = this.n1.j;
                U(cVar, this.s);
                V.p(this.s, true);
                com.onetrust.otpublishers.headless.UI.mobiledatautils.b bVar3 = this.n1;
                com.onetrust.otpublishers.headless.UI.Helper.c cVar2 = bVar3.k;
                com.onetrust.otpublishers.headless.UI.Helper.c cVar3 = bVar3.l;
                com.onetrust.otpublishers.headless.UI.Helper.c cVar4 = bVar3.m;
                R(cVar2.s, cVar3.s, cVar4.s);
                S(cVar2, this.B);
                S(cVar3, this.D);
                S(cVar4, this.C);
            } catch (RuntimeException e2) {
                e = e2;
            }
            try {
                this.A.setAdapter(new com.onetrust.otpublishers.headless.UI.adapter.m(this.L, this.n1, this.W, this.c1, this, this.d1));
                String str3 = this.n1.r;
                this.K.setBackgroundColor(Color.parseColor(str3));
                this.A.setBackgroundColor(Color.parseColor(str3));
                this.M.setBackgroundColor(Color.parseColor(str3));
                OTLogger.c("OT_Automation", 3, "BG color PC: " + str3);
                T(this.n1.n, this.F, this.I, this.J);
                Y();
                if (this.n1.J) {
                    View view = this.l1;
                    ViewGroup.LayoutParams layoutParams = view.getLayoutParams();
                    if (layoutParams != null) {
                        layoutParams.height = 10;
                    }
                    view.setLayoutParams(layoutParams);
                    View view2 = this.g1;
                    ViewGroup.LayoutParams layoutParams2 = view2.getLayoutParams();
                    if (layoutParams2 != null) {
                        layoutParams2.height = 10;
                    }
                    view2.setLayoutParams(layoutParams2);
                    View view3 = this.h1;
                    ViewGroup.LayoutParams layoutParams3 = view3.getLayoutParams();
                    if (layoutParams3 != null) {
                        layoutParams3.height = 10;
                    }
                    view3.setLayoutParams(layoutParams3);
                    View view4 = this.i1;
                    ViewGroup.LayoutParams layoutParams4 = view4.getLayoutParams();
                    if (layoutParams4 != null) {
                        layoutParams4.height = 10;
                    }
                    view4.setLayoutParams(layoutParams4);
                }
                this.j1.setVisibility(cVar.p);
                X();
                this.n1.c(this.m1, this.d1);
                a0();
                return viewJ;
            } catch (RuntimeException e3) {
                e = e3;
                runtimeException = e;
                OTLogger.c("PreferenceCenter", 6, "error while populating  PC fields" + runtimeException.getMessage());
                return viewJ;
            }
        }
        return viewJ;
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, androidx.fragment.app.Fragment
    public final void onDestroyView() {
        super.onDestroyView();
        this.c1 = null;
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t
    public final void p(int i) {
        if (i == 1) {
            Q(i, false);
        }
        if (i == 3) {
            com.google.firebase.perf.logging.b bVar = D.D;
            com.onetrust.otpublishers.headless.Internal.Event.a aVar = this.c1;
            OTConfiguration oTConfiguration = this.d1;
            bVar.getClass();
            D dA = com.google.firebase.perf.logging.b.a(aVar, oTConfiguration);
            this.X = dA;
            dA.R(this.W);
        }
    }
}

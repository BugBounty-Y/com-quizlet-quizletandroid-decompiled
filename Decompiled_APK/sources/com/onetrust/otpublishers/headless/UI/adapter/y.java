package com.onetrust.otpublishers.headless.UI.adapter;

import android.content.Context;
import android.graphics.Color;
import android.os.Bundle;
import android.view.ViewGroup;
import android.widget.TextView;
import androidx.recyclerview.widget.AbstractC1361d0;
import androidx.recyclerview.widget.F0;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3617f4;
import com.google.android.gms.measurement.internal.Z;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.onetrust.otpublishers.headless.Public.Keys.OTFragmentTags;
import com.quizlet.quizletandroid.R;
import java.util.ArrayList;
import org.json.JSONException;

/* loaded from: classes2.dex */
public final class y extends AbstractC1361d0 implements com.onetrust.otpublishers.headless.UI.a {
    public final /* synthetic */ int a;
    public final String b;
    public final Context c;
    public final String d;
    public final String e;
    public final ArrayList f;
    public final com.onetrust.otpublishers.headless.UI.fragment.u g;
    public final com.onetrust.otpublishers.headless.Internal.Helper.k h;
    public final androidx.profileinstaller.a i;
    public final boolean j;
    public final com.onetrust.otpublishers.headless.UI.UIProperty.e k;

    public y(Context context, ArrayList arrayList, String str, String str2, com.onetrust.otpublishers.headless.UI.UIProperty.e eVar, String str3, com.onetrust.otpublishers.headless.UI.fragment.u uVar, com.onetrust.otpublishers.headless.Internal.Helper.k kVar, boolean z, int i) {
        this.a = i;
        switch (i) {
            case 1:
                this.c = context;
                this.f = arrayList;
                this.e = str;
                this.d = str2;
                this.b = str3;
                this.k = eVar;
                this.g = uVar;
                this.h = kVar;
                this.j = z;
                try {
                    this.i = new com.onetrust.otpublishers.headless.UI.UIProperty.f(context).b(kVar, assistantMode.utils.studiableMetadata.b.d(context, null));
                    break;
                } catch (JSONException e) {
                    OTLogger.c("OneTrust", 6, "error in parsing ucp data " + e.getMessage());
                    return;
                }
            default:
                this.c = context;
                this.f = arrayList;
                this.e = str;
                this.d = str2;
                this.b = str3;
                this.k = eVar;
                this.g = uVar;
                this.h = kVar;
                this.j = z;
                try {
                    this.i = new com.onetrust.otpublishers.headless.UI.UIProperty.f(context).b(kVar, assistantMode.utils.studiableMetadata.b.d(context, null));
                    break;
                } catch (JSONException e2) {
                    OTLogger.c("OneTrust", 6, "error in parsing ucp data " + e2.getMessage());
                }
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final int getItemCount() {
        switch (this.a) {
        }
        return this.f.size();
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final void onBindViewHolder(F0 f0, int i) {
        switch (this.a) {
            case 0:
                x xVar = (x) f0;
                com.onetrust.otpublishers.headless.UI.DataModels.b bVar = (com.onetrust.otpublishers.headless.UI.DataModels.b) this.f.get(xVar.getAdapterPosition());
                com.onetrust.otpublishers.headless.UI.UIProperty.e eVar = this.k;
                String str = (String) eVar.t.b;
                boolean zJ = com.onetrust.otpublishers.headless.Internal.a.j(str);
                String str2 = this.b;
                if (zJ) {
                    str = str2;
                }
                String str3 = bVar.b;
                TextView textView = xVar.b;
                if (str3 != null) {
                    textView.setText(str3);
                }
                if (str != null) {
                    textView.setTextColor(Color.parseColor(str));
                }
                androidx.navigation.internal.m mVar = eVar.l;
                if (!com.onetrust.otpublishers.headless.Internal.a.j((String) ((com.google.android.gms.cloudmessaging.k) mVar.d).d)) {
                    textView.setTextSize(Float.parseFloat((String) ((com.google.android.gms.cloudmessaging.k) mVar.d).d));
                }
                String str4 = (String) this.i.d;
                TextView textView2 = xVar.a;
                if (str4 != null) {
                    textView2.setText(str4);
                }
                if (str != null) {
                    textView2.setTextColor(Color.parseColor(str));
                }
                androidx.navigation.internal.m mVar2 = eVar.l;
                if (!com.onetrust.otpublishers.headless.Internal.a.j((String) ((com.google.android.gms.cloudmessaging.k) mVar2.d).d)) {
                    textView2.setTextSize(Float.parseFloat((String) ((com.google.android.gms.cloudmessaging.k) mVar2.d).d));
                }
                String str5 = eVar.g;
                if (!com.onetrust.otpublishers.headless.Internal.a.j(str5)) {
                    str2 = str5;
                }
                if (str2 != null) {
                    AbstractC3617f4.f(textView2, str2);
                }
                com.onetrust.otpublishers.headless.UI.fragment.v vVar = new com.onetrust.otpublishers.headless.UI.fragment.v();
                Bundle bundle = new Bundle();
                bundle.putString(OTFragmentTags.FRAGMENT_TAG, OTFragmentTags.OT_CONSENT_PREF_OPTION_FRAGMENT_TAG);
                vVar.setArguments(bundle);
                xVar.c.setOnClickListener(new com.braze.ui.contentcards.view.a(this, vVar, xVar, 2));
                break;
            default:
                C c = (C) f0;
                com.onetrust.otpublishers.headless.UI.DataModels.e eVar2 = (com.onetrust.otpublishers.headless.UI.DataModels.e) this.f.get(c.getAdapterPosition());
                com.onetrust.otpublishers.headless.UI.UIProperty.e eVar3 = this.k;
                String str6 = (String) eVar3.t.b;
                boolean zJ2 = com.onetrust.otpublishers.headless.Internal.a.j(str6);
                String str7 = this.b;
                if (zJ2) {
                    str6 = str7;
                }
                String str8 = eVar2.a;
                TextView textView3 = c.b;
                if (str8 != null) {
                    textView3.setText(str8);
                }
                if (str6 != null) {
                    textView3.setTextColor(Color.parseColor(str6));
                }
                androidx.navigation.internal.m mVar3 = eVar3.l;
                if (!com.onetrust.otpublishers.headless.Internal.a.j((String) ((com.google.android.gms.cloudmessaging.k) mVar3.d).d)) {
                    textView3.setTextSize(Float.parseFloat((String) ((com.google.android.gms.cloudmessaging.k) mVar3.d).d));
                }
                String str9 = (String) this.i.d;
                TextView textView4 = c.a;
                if (str9 != null) {
                    textView4.setText(str9);
                }
                if (str6 != null) {
                    textView4.setTextColor(Color.parseColor(str6));
                }
                androidx.navigation.internal.m mVar4 = eVar3.l;
                if (!com.onetrust.otpublishers.headless.Internal.a.j((String) ((com.google.android.gms.cloudmessaging.k) mVar4.d).d)) {
                    textView4.setTextSize(Float.parseFloat((String) ((com.google.android.gms.cloudmessaging.k) mVar4.d).d));
                }
                String str10 = eVar3.g;
                if (!com.onetrust.otpublishers.headless.Internal.a.j(str10)) {
                    str7 = str10;
                }
                if (str7 != null) {
                    AbstractC3617f4.f(textView4, str7);
                }
                com.onetrust.otpublishers.headless.UI.fragment.v vVar2 = new com.onetrust.otpublishers.headless.UI.fragment.v();
                Bundle bundle2 = new Bundle();
                bundle2.putString(OTFragmentTags.FRAGMENT_TAG, OTFragmentTags.OT_CONSENT_PREF_FRAGMENT_TAG);
                vVar2.setArguments(bundle2);
                c.c.setOnClickListener(new com.braze.ui.contentcards.view.a(this, vVar2, c, 3));
                break;
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final F0 onCreateViewHolder(ViewGroup viewGroup, int i) {
        switch (this.a) {
            case 0:
                return new x(Z.c(viewGroup, R.layout.ot_uc_purposes_item_list, viewGroup, false));
            default:
                return new C(Z.c(viewGroup, R.layout.ot_uc_purposes_item_list, viewGroup, false));
        }
    }

    @Override // com.onetrust.otpublishers.headless.UI.a
    public final void p(int i) {
        switch (this.a) {
            case 0:
                com.onetrust.otpublishers.headless.UI.fragment.u uVar = this.g;
                if (uVar != null) {
                    uVar.p(i);
                    break;
                }
                break;
            default:
                com.onetrust.otpublishers.headless.UI.fragment.u uVar2 = this.g;
                if (uVar2 != null) {
                    uVar2.p(i);
                    break;
                }
                break;
        }
    }
}

package com.onetrust.otpublishers.headless.UI.TVUI.adapter;

import android.content.Context;
import android.content.res.Resources;
import android.graphics.Color;
import android.graphics.drawable.Drawable;
import android.view.LayoutInflater;
import android.view.ViewGroup;
import android.widget.TextView;
import androidx.appcompat.widget.SwitchCompat;
import androidx.fragment.app.Fragment;
import androidx.recyclerview.widget.AbstractC1361d0;
import androidx.recyclerview.widget.F0;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3617f4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.T;
import com.google.android.gms.measurement.internal.Z;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK;
import com.onetrust.otpublishers.headless.UI.adapter.ViewOnClickListenerC4049e;
import com.quizlet.quizletandroid.R;
import java.util.ArrayList;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class l extends AbstractC1361d0 implements com.onetrust.otpublishers.headless.UI.a {
    public final /* synthetic */ int a;
    public String b;
    public final Context c;
    public final Object d;
    public Object e;
    public final Object f;
    public final Object g;
    public final Object h;
    public final Object i;

    public l(Context context, androidx.profileinstaller.a aVar, com.onetrust.otpublishers.headless.UI.UIProperty.e eVar, String str, com.onetrust.otpublishers.headless.UI.fragment.u uVar, com.onetrust.otpublishers.headless.Internal.Helper.k kVar) {
        this.a = 1;
        this.c = context;
        this.i = eVar;
        this.g = (ArrayList) aVar.i;
        this.f = str;
        this.d = uVar;
        this.h = kVar;
    }

    public static void d(k kVar, String str, String str2) {
        kVar.f.setBackgroundColor(Color.parseColor(str2));
        kVar.b.setTextColor(Color.parseColor(str));
        kVar.c.setTextColor(Color.parseColor(str));
        kVar.a.setTextColor(Color.parseColor(str));
        kVar.d.setTextColor(Color.parseColor(str));
        kVar.e.getDrawable().setTint(Color.parseColor(str));
    }

    public void f(k kVar, JSONObject jSONObject) {
        try {
            Context context = this.c;
            JSONObject jSONObject2 = (JSONObject) this.d;
            com.onetrust.otpublishers.headless.UI.TVUI.datautils.c cVar = (com.onetrust.otpublishers.headless.UI.TVUI.datautils.c) this.i;
            String strM = assistantMode.utils.studiableMetadata.b.m(context, jSONObject2, jSONObject, cVar.f, cVar.e);
            if (com.onetrust.otpublishers.headless.Internal.a.j(strM)) {
                kVar.c.setVisibility(8);
            } else {
                kVar.c.setText(strM);
                kVar.c.setVisibility(0);
            }
        } catch (JSONException e) {
            T.d(e, new StringBuilder("Error on displaying vendor count on TV pc details page. Error = "), this.b, 6);
        }
    }

    public void g(com.onetrust.otpublishers.headless.UI.adapter.w wVar, com.onetrust.otpublishers.headless.UI.DataModels.c cVar, boolean z) {
        com.onetrust.otpublishers.headless.UI.adapter.y yVar = new com.onetrust.otpublishers.headless.UI.adapter.y(this.c, cVar.i, this.b, (String) this.e, (com.onetrust.otpublishers.headless.UI.UIProperty.e) this.i, (String) this.f, (com.onetrust.otpublishers.headless.UI.fragment.u) this.d, (com.onetrust.otpublishers.headless.Internal.Helper.k) this.h, z, 1);
        com.onetrust.otpublishers.headless.UI.adapter.y yVar2 = new com.onetrust.otpublishers.headless.UI.adapter.y(this.c, cVar.j, this.b, (String) this.e, (com.onetrust.otpublishers.headless.UI.UIProperty.e) this.i, (String) this.f, (com.onetrust.otpublishers.headless.UI.fragment.u) this.d, (com.onetrust.otpublishers.headless.Internal.Helper.k) this.h, z, 0);
        wVar.d.setAdapter(yVar);
        wVar.e.setAdapter(yVar2);
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final int getItemCount() {
        switch (this.a) {
            case 0:
                JSONArray jSONArray = (JSONArray) this.f;
                if (jSONArray != null) {
                    return jSONArray.length();
                }
                return 0;
            default:
                return ((ArrayList) this.g).size();
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public long getItemId(int i) {
        switch (this.a) {
            case 1:
                return i;
            default:
                return super.getItemId(i);
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final void onBindViewHolder(F0 f0, int i) throws JSONException, Resources.NotFoundException {
        Drawable thumbDrawable;
        int color;
        Drawable thumbDrawable2;
        int color2;
        switch (this.a) {
            case 0:
                k kVar = (k) f0;
                com.onetrust.otpublishers.headless.UI.TVUI.datautils.c cVar = (com.onetrust.otpublishers.headless.UI.TVUI.datautils.c) this.i;
                String str = "GroupNameOTT";
                JSONArray jSONArray = (JSONArray) this.f;
                try {
                    String strOptString = jSONArray.getJSONObject(kVar.getAdapterPosition()).optString("Type");
                    boolean zContains = jSONArray.getJSONObject(kVar.getAdapterPosition()).optString("Status").contains("always");
                    TextView textView = kVar.a;
                    TextView textView2 = kVar.d;
                    if (zContains || strOptString.equals("IAB2_SPL_PURPOSE") || strOptString.equals("IAB2V2_SPL_PURPOSE") || strOptString.equals("IAB2_FEATURE") || strOptString.equals("IAB2V2_FEATURE")) {
                        textView2.setVisibility(0);
                        com.onetrust.otpublishers.headless.UI.TVUI.datautils.c cVarI = com.onetrust.otpublishers.headless.UI.TVUI.datautils.c.i();
                        String str2 = (String) cVarI.j.u.g;
                        if (str2 == null) {
                            str2 = cVarI.b;
                        }
                        textView2.setText(str2);
                        textView.setVisibility(8);
                    } else {
                        textView2.setVisibility(8);
                        textView.setVisibility(0);
                    }
                    JSONObject jSONObject = jSONArray.getJSONObject(kVar.getAdapterPosition());
                    Context context = this.c;
                    TextView textView3 = kVar.b;
                    if (com.onetrust.otpublishers.headless.Internal.a.j(jSONObject.optString("GroupNameOTT"))) {
                        str = "GroupName";
                    }
                    assistantMode.utils.studiableMetadata.b.r(context, textView3, jSONObject.optString(str));
                    kVar.e.setVisibility(0);
                    f(kVar, jSONObject);
                    int purposeConsentLocal = ((OTPublishersHeadlessSDK) this.g).getPurposeConsentLocal(jSONArray.getJSONObject(i).optString("CustomGroupId", ""));
                    com.onetrust.otpublishers.headless.UI.TVUI.datautils.b bVar = (com.onetrust.otpublishers.headless.UI.TVUI.datautils.b) this.h;
                    textView.setText(purposeConsentLocal == 1 ? bVar.b : bVar.c);
                    String strJ = AbstractC3617f4.j(cVar.a());
                    d(kVar, cVar.l(), strJ);
                    kVar.itemView.setOnFocusChangeListener(new com.onetrust.otpublishers.headless.Internal.syncnotif.c(this, kVar, strJ, 3));
                } catch (JSONException e) {
                    Z.p("Error while rendering subgroup ", e, "OneTrust", 6);
                }
                kVar.itemView.setOnKeyListener(new ViewOnKeyListenerC4043a(this, kVar, 1));
                break;
            default:
                com.onetrust.otpublishers.headless.UI.adapter.w wVar = (com.onetrust.otpublishers.headless.UI.adapter.w) f0;
                int adapterPosition = wVar.getAdapterPosition();
                com.onetrust.otpublishers.headless.UI.DataModels.c cVar2 = (com.onetrust.otpublishers.headless.UI.DataModels.c) ((ArrayList) this.g).get(adapterPosition);
                RecyclerView recyclerView = wVar.e;
                recyclerView.getContext();
                LinearLayoutManager linearLayoutManager = new LinearLayoutManager(1);
                linearLayoutManager.C = cVar2.j.size();
                recyclerView.setLayoutManager(linearLayoutManager);
                RecyclerView recyclerView2 = wVar.d;
                recyclerView2.getContext();
                LinearLayoutManager linearLayoutManager2 = new LinearLayoutManager(1);
                linearLayoutManager2.C = cVar2.i.size();
                recyclerView2.setLayoutManager(linearLayoutManager2);
                if (!com.onetrust.otpublishers.headless.Internal.a.j(cVar2.b)) {
                    this.b = cVar2.b;
                }
                if (!com.onetrust.otpublishers.headless.Internal.a.j(cVar2.c)) {
                    this.e = cVar2.c;
                }
                OTLogger.c("OTConsentPreferencesAdapter", 3, "error in setting subgroup consent parent " + cVar2.i.size());
                recyclerView.setRecycledViewPool(null);
                recyclerView2.setRecycledViewPool(null);
                boolean z = ((com.onetrust.otpublishers.headless.Internal.Helper.k) this.h).u(cVar2.a) == 1;
                SwitchCompat switchCompat = wVar.c;
                switchCompat.setChecked(z);
                com.onetrust.otpublishers.headless.UI.UIProperty.e eVar = (com.onetrust.otpublishers.headless.UI.UIProperty.e) this.i;
                String str3 = eVar.b;
                if (!com.onetrust.otpublishers.headless.Internal.a.j(str3)) {
                    wVar.f.setBackgroundColor(Color.parseColor(str3));
                }
                Context context2 = this.c;
                if (z) {
                    switchCompat.getTrackDrawable().setTint(context2.getColor(R.color.light_greyOT));
                    if (com.onetrust.otpublishers.headless.Internal.a.j(eVar.c)) {
                        thumbDrawable2 = switchCompat.getThumbDrawable();
                        color2 = context2.getColor(R.color.colorPrimaryOT);
                    } else {
                        thumbDrawable2 = switchCompat.getThumbDrawable();
                        color2 = Color.parseColor(eVar.c);
                    }
                    thumbDrawable2.setTint(color2);
                } else {
                    switchCompat.getTrackDrawable().setTint(context2.getColor(R.color.light_greyOT));
                    if (com.onetrust.otpublishers.headless.Internal.a.j(eVar.d)) {
                        thumbDrawable = switchCompat.getThumbDrawable();
                        color = context2.getColor(R.color.contentTextColorOT);
                    } else {
                        thumbDrawable = switchCompat.getThumbDrawable();
                        color = Color.parseColor(eVar.d);
                    }
                    thumbDrawable.setTint(color);
                }
                androidx.navigation.internal.m mVar = eVar.t;
                String str4 = this.b;
                String str5 = (String) mVar.b;
                boolean zJ = com.onetrust.otpublishers.headless.Internal.a.j(str5);
                String str6 = (String) this.f;
                if (zJ) {
                    str5 = str6;
                }
                int color3 = Color.parseColor(str5);
                TextView textView4 = wVar.b;
                textView4.setTextColor(color3);
                textView4.setText(str4);
                if (!com.onetrust.otpublishers.headless.Internal.a.j((String) ((com.google.android.gms.cloudmessaging.k) mVar.d).d)) {
                    textView4.setTextSize(Float.parseFloat((String) ((com.google.android.gms.cloudmessaging.k) mVar.d).d));
                }
                androidx.navigation.internal.m mVar2 = eVar.t;
                String str7 = (String) this.e;
                String str8 = (String) mVar2.b;
                if (!com.onetrust.otpublishers.headless.Internal.a.j(str8)) {
                    str6 = str8;
                }
                int color4 = Color.parseColor(str6);
                TextView textView5 = wVar.a;
                textView5.setTextColor(color4);
                textView5.setText(str7);
                if (!com.onetrust.otpublishers.headless.Internal.a.j((String) ((com.google.android.gms.cloudmessaging.k) mVar2.d).d)) {
                    textView5.setTextSize(Float.parseFloat((String) ((com.google.android.gms.cloudmessaging.k) mVar2.d).d));
                }
                androidx.navigation.internal.m mVar3 = eVar.l;
                if (!com.onetrust.otpublishers.headless.Internal.a.j((String) ((com.google.android.gms.cloudmessaging.k) mVar3.d).d)) {
                    textView5.setTextSize(Float.parseFloat((String) ((com.google.android.gms.cloudmessaging.k) mVar3.d).d));
                }
                switchCompat.setOnClickListener(new ViewOnClickListenerC4049e(this, cVar2, wVar, adapterPosition));
                g(wVar, cVar2, switchCompat.isChecked());
                break;
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final F0 onCreateViewHolder(ViewGroup viewGroup, int i) {
        switch (this.a) {
            case 0:
                return new k(LayoutInflater.from(this.c).inflate(R.layout.ot_pc_groupitem_tv, viewGroup, false));
            default:
                return new com.onetrust.otpublishers.headless.UI.adapter.w(Z.c(viewGroup, R.layout.ot_uc_purposes_list, viewGroup, false));
        }
    }

    @Override // com.onetrust.otpublishers.headless.UI.a
    public void p(int i) {
        com.onetrust.otpublishers.headless.UI.fragment.u uVar = (com.onetrust.otpublishers.headless.UI.fragment.u) this.d;
        if (uVar != null) {
            uVar.p(i);
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    public l(JSONArray jSONArray, Context context, OTPublishersHeadlessSDK oTPublishersHeadlessSDK, j jVar, JSONObject jSONObject) {
        this.a = 0;
        this.b = "OTPCSubGroupTVAdapter";
        this.c = context;
        this.f = jSONArray;
        this.g = oTPublishersHeadlessSDK;
        this.e = (Fragment) jVar;
        this.h = com.onetrust.otpublishers.headless.UI.TVUI.datautils.b.a();
        this.i = com.onetrust.otpublishers.headless.UI.TVUI.datautils.c.i();
        this.d = jSONObject;
    }
}

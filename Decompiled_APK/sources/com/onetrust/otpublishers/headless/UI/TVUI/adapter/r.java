package com.onetrust.otpublishers.headless.UI.TVUI.adapter;

import android.content.Context;
import android.graphics.Color;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.recyclerview.widget.AbstractC1361d0;
import androidx.recyclerview.widget.F0;
import com.google.android.gms.internal.mlkit_vision_document_scanner.P;
import com.google.android.gms.measurement.internal.Z;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.quizlet.quizletandroid.R;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Locale;
import java.util.regex.Pattern;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class r extends AbstractC1361d0 {
    public static final Pattern i = Pattern.compile("([a-f]).*");
    public static final Pattern j = Pattern.compile("([g-l]).*");
    public static final Pattern k = Pattern.compile("([m-r]).*");
    public static final Pattern l = Pattern.compile("([s-z]).*");
    public final com.onetrust.otpublishers.headless.UI.TVUI.fragments.n a;
    public ArrayList d;
    public int e;
    public ArrayList f;
    public ArrayList g;
    public final Context h;
    public final com.onetrust.otpublishers.headless.UI.TVUI.datautils.c c = com.onetrust.otpublishers.headless.UI.TVUI.datautils.c.i();
    public final JSONArray b = P.g((JSONObject) com.onetrust.otpublishers.headless.UI.TVUI.datautils.d.a().a);

    public r(Context context, com.onetrust.otpublishers.headless.UI.TVUI.fragments.n nVar, ArrayList arrayList) {
        this.d = new ArrayList();
        this.a = nVar;
        this.d = arrayList;
        this.h = context;
    }

    public final ArrayList d() {
        Context context = this.h;
        new com.onetrust.otpublishers.headless.Internal.Preferences.d(context);
        new com.onetrust.otpublishers.headless.Internal.Preferences.e(context);
        new com.onetrust.otpublishers.headless.Internal.Models.b(context);
        JSONArray jSONArrayA = com.onetrust.otpublishers.headless.Internal.Helper.j.a(this.b, this.d);
        this.f = new ArrayList();
        if (this.g == null) {
            this.g = new ArrayList();
        }
        if (retrofit2.adapter.rxjava3.d.l(jSONArrayA)) {
            OTLogger.c("TVSdkList", 6, "setSDKListData: Empty data found for SDKs");
            return null;
        }
        for (int i2 = 0; i2 < jSONArrayA.length(); i2++) {
            try {
                JSONObject jSONObject = jSONArrayA.getJSONObject(i2);
                if (this.g.isEmpty()) {
                    this.f.add(jSONObject);
                } else {
                    f(this.f, jSONObject);
                }
            } catch (JSONException e) {
                Z.o("error while constructing SDK List json object lists,err : ", e, "TVSdkList");
            }
        }
        Collections.sort(this.f, new com.google.zxing.aztec.encoder.c(2));
        return this.f;
    }

    public final void f(ArrayList arrayList, JSONObject jSONObject) {
        String strTrim = jSONObject.getString("Name").toLowerCase(Locale.ENGLISH).trim();
        if (this.g.contains("A_F") && i.matcher(strTrim).matches()) {
            arrayList.add(jSONObject);
        }
        if (this.g.contains("G_L") && j.matcher(strTrim).matches()) {
            arrayList.add(jSONObject);
        }
        if (this.g.contains("M_R") && k.matcher(strTrim).matches()) {
            arrayList.add(jSONObject);
        }
        if (this.g.contains("S_Z") && l.matcher(strTrim).matches()) {
            arrayList.add(jSONObject);
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final int getItemCount() {
        return this.f.size();
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final void onBindViewHolder(F0 f0, int i2) {
        JSONException e;
        JSONObject jSONObject;
        q qVar = (q) f0;
        int adapterPosition = qVar.getAdapterPosition();
        OTLogger.c("TVSdkList", 2, "filtered sdks count " + this.f.size());
        JSONObject jSONObject2 = new JSONObject();
        ArrayList arrayList = this.f;
        TextView textView = qVar.a;
        LinearLayout linearLayout = qVar.b;
        if (arrayList != null) {
            try {
                qVar.setIsRecyclable(false);
                jSONObject = (JSONObject) this.f.get(adapterPosition);
                try {
                    assistantMode.utils.studiableMetadata.b.r(linearLayout.getContext(), textView, jSONObject.getString("Name"));
                } catch (JSONException e2) {
                    e = e2;
                    Z.p("exception thrown when rendering SDKs, err : ", e, "OneTrust", 6);
                    jSONObject2 = jSONObject;
                    com.onetrust.otpublishers.headless.UI.TVUI.datautils.c cVar = this.c;
                    textView.setTextColor(Color.parseColor((String) cVar.j.B.c));
                    linearLayout.setBackgroundColor(Color.parseColor((String) cVar.j.B.b));
                    qVar.itemView.setOnFocusChangeListener(new com.onetrust.otpublishers.headless.Internal.syncnotif.c(this, jSONObject2, qVar, 4));
                    qVar.itemView.setOnKeyListener(new ViewOnKeyListenerC4043a(this, qVar, 2));
                }
            } catch (JSONException e3) {
                e = e3;
                jSONObject = jSONObject2;
            }
            jSONObject2 = jSONObject;
        }
        com.onetrust.otpublishers.headless.UI.TVUI.datautils.c cVar2 = this.c;
        textView.setTextColor(Color.parseColor((String) cVar2.j.B.c));
        linearLayout.setBackgroundColor(Color.parseColor((String) cVar2.j.B.b));
        qVar.itemView.setOnFocusChangeListener(new com.onetrust.otpublishers.headless.Internal.syncnotif.c(this, jSONObject2, qVar, 4));
        qVar.itemView.setOnKeyListener(new ViewOnKeyListenerC4043a(this, qVar, 2));
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final F0 onCreateViewHolder(ViewGroup viewGroup, int i2) {
        return new q(Z.c(viewGroup, R.layout.ot_pc_list_item_tv, viewGroup, false));
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final void onViewAttachedToWindow(F0 f0) {
        q qVar = (q) f0;
        super.onViewAttachedToWindow(qVar);
        if (qVar.getAdapterPosition() == this.e) {
            qVar.itemView.requestFocus();
        }
    }
}

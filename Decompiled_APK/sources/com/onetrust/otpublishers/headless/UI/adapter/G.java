package com.onetrust.otpublishers.headless.UI.adapter;

import android.graphics.Color;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.graphics.Typeface;
import android.graphics.drawable.Drawable;
import android.view.ViewGroup;
import android.widget.TextView;
import androidx.recyclerview.widget.AbstractC1361d0;
import androidx.recyclerview.widget.F0;
import com.google.android.gms.internal.ads.C3;
import com.google.android.gms.measurement.internal.Z;
import com.onetrust.otpublishers.headless.Public.DataModel.OTConfiguration;
import com.onetrust.otpublishers.headless.Public.OTVendorListMode;
import com.quizlet.quizletandroid.R;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class G extends AbstractC1361d0 {
    public final OTConfiguration a;
    public final String b;
    public final JSONArray c;
    public final JSONObject d;
    public final String e;
    public final C3 f;
    public final String g = OTVendorListMode.IAB;

    public G(JSONArray jSONArray, String str, C3 c3, OTConfiguration oTConfiguration, JSONObject jSONObject, String str2) {
        this.c = jSONArray;
        this.d = jSONObject;
        this.e = str;
        this.f = c3;
        this.a = oTConfiguration;
        this.b = str2;
    }

    public final String d(F f, String str) throws JSONException {
        int adapterPosition = f.getAdapterPosition();
        JSONArray jSONArray = this.c;
        String string = jSONArray.getJSONObject(adapterPosition).getString(str);
        JSONObject jSONObject = this.d;
        if (jSONObject != null) {
            String strOptString = jSONObject.optString(jSONArray.getJSONObject(f.getAdapterPosition()).getString("id"));
            if (!com.onetrust.otpublishers.headless.Internal.a.j(strOptString) && Integer.parseInt(strOptString) >= 0) {
                StringBuilder sb = new StringBuilder();
                sb.append(string);
                sb.append(" (");
                sb.append(strOptString);
                sb.append(" ");
                return android.support.v4.media.session.a.t(sb, this.b, ")");
            }
        }
        return string;
    }

    public final void f(F f) {
        OTConfiguration oTConfiguration;
        Typeface otTypeFaceMap;
        C3 c3 = this.f;
        if (!com.onetrust.otpublishers.headless.Internal.a.j((String) ((com.google.android.gms.cloudmessaging.k) ((androidx.navigation.internal.m) c3.g).d).d)) {
            f.a.setTextSize(Float.parseFloat((String) ((com.google.android.gms.cloudmessaging.k) ((androidx.navigation.internal.m) c3.g).d).d));
        }
        if (!com.onetrust.otpublishers.headless.Internal.a.j((String) ((androidx.navigation.internal.m) c3.g).f)) {
            f.a.setTextAlignment(Integer.parseInt((String) ((androidx.navigation.internal.m) c3.g).f));
        }
        com.google.android.gms.cloudmessaging.k kVar = (com.google.android.gms.cloudmessaging.k) ((androidx.navigation.internal.m) c3.g).d;
        TextView textView = f.a;
        String str = (String) kVar.e;
        if (!com.onetrust.otpublishers.headless.Internal.a.j(str) && (oTConfiguration = this.a) != null && (otTypeFaceMap = oTConfiguration.getOtTypeFaceMap(str)) != null) {
            textView.setTypeface(otTypeFaceMap);
        } else {
            int iA = com.google.android.gms.cloudmessaging.k.a(textView, kVar.b);
            textView.setTypeface(!com.onetrust.otpublishers.headless.Internal.a.j((String) kVar.c) ? Typeface.create((String) kVar.c, iA) : Typeface.create(textView.getTypeface(), iA));
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final int getItemCount() {
        return this.c.length();
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final void onBindViewHolder(F0 f0, int i) {
        String str = this.e;
        F f = (F) f0;
        f.setIsRecyclable(false);
        TextView textView = f.a;
        try {
            textView.setText(d(f, OTVendorListMode.GENERAL.equalsIgnoreCase(this.g) ? "Name" : "name"));
            textView.setTextColor(Color.parseColor(str));
            for (Drawable drawable : textView.getCompoundDrawablesRelative()) {
                if (drawable != null) {
                    drawable.setColorFilter(new PorterDuffColorFilter(Color.parseColor(str), PorterDuff.Mode.SRC_IN));
                }
            }
            if (this.f != null) {
                f(f);
            }
        } catch (Exception e) {
            Z.n("error while rendering purpose items in Vendor detail screen ", e, "OneTrust", 6);
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final F0 onCreateViewHolder(ViewGroup viewGroup, int i) {
        return new F(Z.c(viewGroup, R.layout.ot_vendor_details_purpose_item, viewGroup, false));
    }
}

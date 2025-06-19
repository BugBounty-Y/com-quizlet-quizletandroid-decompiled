package com.onetrust.otpublishers.headless.UI.TVUI.adapter;

import android.graphics.Color;
import android.view.ViewGroup;
import android.widget.TextView;
import androidx.recyclerview.widget.AbstractC1361d0;
import androidx.recyclerview.widget.F0;
import com.google.android.gms.measurement.internal.Z;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK;
import com.onetrust.otpublishers.headless.Public.OTVendorListMode;
import com.onetrust.otpublishers.headless.Public.uiutils.OTVendorUtils;
import com.quizlet.quizletandroid.R;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Locale;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class c extends AbstractC1361d0 {
    public final com.onetrust.otpublishers.headless.UI.TVUI.fragments.s a;
    public final OTPublishersHeadlessSDK b;
    public final OTVendorUtils c;
    public final com.onetrust.otpublishers.headless.UI.TVUI.datautils.c d = com.onetrust.otpublishers.headless.UI.TVUI.datautils.c.i();
    public int e;
    public JSONObject f;
    public ArrayList g;
    public ArrayList h;

    public c(OTVendorUtils oTVendorUtils, com.onetrust.otpublishers.headless.UI.TVUI.fragments.s sVar, OTPublishersHeadlessSDK oTPublishersHeadlessSDK) {
        this.c = oTVendorUtils;
        this.a = sVar;
        this.b = oTPublishersHeadlessSDK;
        oTVendorUtils.refreshList(OTVendorListMode.GOOGLE);
        oTVendorUtils.setVendorsListObject(OTVendorListMode.GOOGLE, d(), false);
    }

    public final JSONObject d() {
        JSONObject jSONObject = new JSONObject();
        JSONObject vendorListUI = this.b.getVendorListUI(OTVendorListMode.GOOGLE);
        if (vendorListUI != null) {
            jSONObject = vendorListUI;
        }
        OTLogger.c("TVGoogleVendors", 3, "Total Google vendors count: " + jSONObject.length());
        return jSONObject;
    }

    public final void f(ArrayList arrayList, JSONObject jSONObject) {
        String lowerCase = jSONObject.getString("name").toLowerCase(Locale.ENGLISH);
        if (this.h.contains("A_F") && lowerCase.matches("(a|b|c|d|e|f]).*")) {
            arrayList.add(jSONObject);
        }
        if (this.h.contains("G_L") && lowerCase.matches("(g|h|i|j|k|l]).*")) {
            arrayList.add(jSONObject);
        }
        if (this.h.contains("M_R") && lowerCase.matches("(m|n|o|p|q|r]).*")) {
            arrayList.add(jSONObject);
        }
        if (this.h.contains("S_Z") && lowerCase.matches("(s|t|u|v|w|x|y|z]).*")) {
            arrayList.add(jSONObject);
        }
    }

    public final void g() {
        JSONObject jSONObjectD = d();
        OTVendorUtils oTVendorUtils = this.c;
        oTVendorUtils.setVendorsListObject(OTVendorListMode.GOOGLE, jSONObjectD, false);
        this.f = new JSONObject();
        this.f = oTVendorUtils.getVendorsListObject(OTVendorListMode.GOOGLE);
        this.g = new ArrayList();
        if (this.h == null) {
            this.h = new ArrayList();
        }
        if (retrofit2.adapter.rxjava3.d.o(this.f)) {
            OTLogger.c("TVGoogleVendors", 6, "setVendorListObject: Empty data found for Vendors");
            return;
        }
        JSONArray jSONArrayNames = this.f.names();
        if (jSONArrayNames == null) {
            OTLogger.c("TVGoogleVendors", 6, "setVendorListObject: Vendor data is empty");
            return;
        }
        for (int i = 0; i < this.f.length(); i++) {
            try {
                JSONObject jSONObject = this.f.getJSONObject(jSONArrayNames.get(i).toString());
                if (this.h.isEmpty()) {
                    this.g.add(jSONObject);
                } else {
                    f(this.g, jSONObject);
                }
            } catch (JSONException e) {
                Z.o("error while constructing VL json object lists,err : ", e, "TVGoogleVendors");
            }
        }
        Collections.sort(this.g, new com.google.zxing.aztec.encoder.c(1));
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final int getItemCount() {
        return this.g.size();
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final void onBindViewHolder(F0 f0, int i) throws JSONException {
        C4044b c4044b = (C4044b) f0;
        int adapterPosition = c4044b.getAdapterPosition();
        JSONArray jSONArrayNames = this.f.names();
        TextView textView = c4044b.a;
        String string = "";
        if (jSONArrayNames != null) {
            try {
                c4044b.setIsRecyclable(false);
                JSONObject jSONObject = (JSONObject) this.g.get(adapterPosition);
                string = jSONObject.getString("id");
                textView.setText(jSONObject.getString("name"));
            } catch (JSONException e) {
                Z.p("exception thrown when rendering vendors, err : ", e, "OneTrust", 6);
            }
        }
        com.onetrust.otpublishers.headless.UI.TVUI.datautils.c cVar = this.d;
        textView.setTextColor(Color.parseColor((String) cVar.j.B.c));
        c4044b.b.setVisibility(8);
        c4044b.c.setBackgroundColor(Color.parseColor((String) cVar.j.B.b));
        c4044b.itemView.setOnFocusChangeListener(new com.onetrust.otpublishers.headless.Internal.syncnotif.c(this, string, c4044b, 2));
        c4044b.itemView.setOnKeyListener(new ViewOnKeyListenerC4043a(this, c4044b, 0));
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final F0 onCreateViewHolder(ViewGroup viewGroup, int i) {
        return new C4044b(Z.c(viewGroup, R.layout.ot_pc_list_item_tv, viewGroup, false));
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final void onViewAttachedToWindow(F0 f0) {
        C4044b c4044b = (C4044b) f0;
        super.onViewAttachedToWindow(c4044b);
        if (c4044b.getAdapterPosition() == this.e) {
            c4044b.itemView.requestFocus();
        }
    }
}

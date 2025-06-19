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
import java.util.HashMap;
import java.util.Locale;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class B extends AbstractC1361d0 {
    public final com.onetrust.otpublishers.headless.UI.TVUI.fragments.s a;
    public final OTPublishersHeadlessSDK b;
    public final OTVendorUtils c;
    public final com.onetrust.otpublishers.headless.UI.TVUI.datautils.c d = com.onetrust.otpublishers.headless.UI.TVUI.datautils.c.i();
    public boolean e;
    public HashMap f;
    public int g;
    public JSONObject h;
    public ArrayList i;
    public ArrayList j;

    public B(OTVendorUtils oTVendorUtils, com.onetrust.otpublishers.headless.UI.TVUI.fragments.s sVar, OTPublishersHeadlessSDK oTPublishersHeadlessSDK, boolean z, HashMap map) {
        this.f = new HashMap();
        this.c = oTVendorUtils;
        this.a = sVar;
        this.b = oTPublishersHeadlessSDK;
        this.e = z;
        this.f = map;
        oTVendorUtils.refreshList(OTVendorListMode.IAB);
        oTVendorUtils.setVendorsListObject(OTVendorListMode.IAB, d(), false);
    }

    public final JSONObject d() {
        JSONObject jSONObject = new JSONObject();
        boolean z = this.e;
        OTPublishersHeadlessSDK oTPublishersHeadlessSDK = this.b;
        if (z) {
            JSONObject vendorsByPurpose = this.c.getVendorsByPurpose(this.f, oTPublishersHeadlessSDK.getVendorListUI(OTVendorListMode.IAB));
            OTLogger.c("TVVendorlist", 3, "Total vendors count with filtered purpose : " + vendorsByPurpose.length());
            return vendorsByPurpose;
        }
        JSONObject vendorListUI = oTPublishersHeadlessSDK.getVendorListUI(OTVendorListMode.IAB);
        if (vendorListUI != null) {
            jSONObject = vendorListUI;
        }
        OTLogger.c("TVVendorlist", 3, "Total IAB vendors count without filter : " + jSONObject.length());
        return jSONObject;
    }

    public final void f(ArrayList arrayList, JSONObject jSONObject) {
        String lowerCase = jSONObject.getString("name").toLowerCase(Locale.ENGLISH);
        if (this.j.contains("A_F") && lowerCase.matches("(a|b|c|d|e|f).*")) {
            arrayList.add(jSONObject);
        }
        if (this.j.contains("G_L") && lowerCase.matches("(g|h|i|j|k|l).*")) {
            arrayList.add(jSONObject);
        }
        if (this.j.contains("M_R") && lowerCase.matches("(m|n|o|p|q|r).*")) {
            arrayList.add(jSONObject);
        }
        if (this.j.contains("S_Z") && lowerCase.matches("(s|t|u|v|w|x|y|z).*")) {
            arrayList.add(jSONObject);
        }
    }

    public final void g() {
        JSONObject jSONObjectD = d();
        OTVendorUtils oTVendorUtils = this.c;
        oTVendorUtils.setVendorsListObject(OTVendorListMode.IAB, jSONObjectD, false);
        this.h = new JSONObject();
        this.h = oTVendorUtils.getVendorsListObject(OTVendorListMode.IAB);
        this.i = new ArrayList();
        if (this.j == null) {
            this.j = new ArrayList();
        }
        if (retrofit2.adapter.rxjava3.d.o(this.h)) {
            OTLogger.c("TVVendorlist", 6, "setVendorListObject: Empty data found for Vendors");
            return;
        }
        JSONArray jSONArrayNames = this.h.names();
        if (jSONArrayNames == null) {
            OTLogger.c("TVVendorlist", 6, "setVendorListObject: Vendor data is empty");
            return;
        }
        for (int i = 0; i < this.h.length(); i++) {
            try {
                JSONObject jSONObject = this.h.getJSONObject(jSONArrayNames.get(i).toString());
                if (this.j.isEmpty()) {
                    this.i.add(jSONObject);
                } else {
                    f(this.i, jSONObject);
                }
            } catch (JSONException e) {
                Z.o("error while constructing VL json object lists,err : ", e, "TVVendorlist");
            }
        }
        Collections.sort(this.i, new com.google.zxing.aztec.encoder.c(3));
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final int getItemCount() {
        return this.i.size();
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final void onBindViewHolder(F0 f0, int i) throws JSONException {
        A a = (A) f0;
        int adapterPosition = a.getAdapterPosition();
        OTLogger.c("TVVendorlist", 2, "filtered vendors count " + this.i.size());
        JSONArray jSONArrayNames = this.h.names();
        TextView textView = a.a;
        String string = "";
        if (jSONArrayNames != null) {
            try {
                a.setIsRecyclable(false);
                JSONObject jSONObject = (JSONObject) this.i.get(adapterPosition);
                string = jSONObject.getString("id");
                textView.setText(jSONObject.getString("name"));
            } catch (JSONException e) {
                Z.p("exception thrown when rendering vendors, err : ", e, "OneTrust", 6);
            }
        }
        com.onetrust.otpublishers.headless.UI.TVUI.datautils.c cVar = this.d;
        textView.setTextColor(Color.parseColor((String) cVar.j.B.c));
        a.b.setVisibility(8);
        a.c.setBackgroundColor(Color.parseColor((String) cVar.j.B.b));
        a.itemView.setOnFocusChangeListener(new com.onetrust.otpublishers.headless.Internal.syncnotif.c(this, string, a, 5));
        a.itemView.setOnKeyListener(new ViewOnKeyListenerC4043a(this, a, 7));
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final F0 onCreateViewHolder(ViewGroup viewGroup, int i) {
        return new A(Z.c(viewGroup, R.layout.ot_pc_list_item_tv, viewGroup, false));
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final void onViewAttachedToWindow(F0 f0) {
        A a = (A) f0;
        super.onViewAttachedToWindow(a);
        if (a.getAdapterPosition() == this.g) {
            a.itemView.requestFocus();
        }
    }
}

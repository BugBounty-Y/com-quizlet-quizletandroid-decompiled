package com.onetrust.otpublishers.headless.UI.TVUI.adapter;

import android.content.Context;
import android.view.ViewGroup;
import androidx.recyclerview.widget.AbstractC1361d0;
import androidx.recyclerview.widget.F0;
import com.google.android.gms.measurement.internal.Z;
import com.quizlet.quizletandroid.R;
import org.json.JSONArray;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class e extends AbstractC1361d0 {
    public final /* synthetic */ int a;
    public Object b;
    public final Object c;
    public final Object d;

    public e(Context context, JSONArray jSONArray, String str) {
        this.a = 0;
        this.b = context;
        this.c = jSONArray;
        this.d = str;
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final int getItemCount() {
        switch (this.a) {
            case 0:
                return ((JSONArray) this.c).length();
            default:
                JSONObject jSONObject = (JSONObject) this.b;
                if (jSONObject == null) {
                    return 0;
                }
                return jSONObject.length();
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public int getItemViewType(int i) {
        switch (this.a) {
            case 1:
                try {
                    JSONArray jSONArrayNames = ((JSONObject) this.b).names();
                    if (jSONArrayNames != null) {
                        return ((JSONObject) this.b).getInt(jSONArrayNames.get(i).toString());
                    }
                } catch (Exception e) {
                    Z.n("error while getting view type ", e, "OneTrust", 6);
                }
                return 0;
            default:
                return super.getItemViewType(i);
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:13:0x0024, code lost:
    
        if (r2 != 5) goto L55;
     */
    @Override // androidx.recyclerview.widget.AbstractC1361d0
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void onBindViewHolder(androidx.recyclerview.widget.F0 r22, int r23) {
        /*
            Method dump skipped, instructions count: 1000
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.UI.TVUI.adapter.e.onBindViewHolder(androidx.recyclerview.widget.F0, int):void");
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final F0 onCreateViewHolder(ViewGroup viewGroup, int i) {
        switch (this.a) {
            case 0:
                return new d(Z.c(viewGroup, R.layout.ot_iab_illustration_details_purpose_tv_item, viewGroup, false));
            default:
                if (i == 1) {
                    return new z(Z.c(viewGroup, R.layout.ot_tv_vendor_details_purpose_title_item, viewGroup, false));
                }
                if (i == 2) {
                    return new y(Z.c(viewGroup, R.layout.ot_tv_vendor_details_purpose_item, viewGroup, false));
                }
                if (i == 3) {
                    return new w(Z.c(viewGroup, R.layout.ot_tv_vendor_disclosure_item, viewGroup, false));
                }
                if (i == 4) {
                    return new x(Z.c(viewGroup, R.layout.ot_tv_vendor_domains_used_item, viewGroup, false));
                }
                if (i == 5) {
                    return new y(Z.c(viewGroup, R.layout.ot_tv_vendor_details_standard_retention_item, viewGroup, false));
                }
                throw new RuntimeException("Invalid view type found");
        }
    }

    public e(JSONObject jSONObject, com.onetrust.otpublishers.headless.UI.TVUI.fragments.p pVar) {
        this.a = 1;
        this.b = jSONObject;
        this.c = com.onetrust.otpublishers.headless.UI.TVUI.datautils.d.a();
        this.d = pVar;
    }
}

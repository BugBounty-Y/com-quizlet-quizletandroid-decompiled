package com.onetrust.otpublishers.headless.UI.TVUI.adapter;

import android.graphics.Color;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.graphics.drawable.Drawable;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import androidx.recyclerview.widget.AbstractC1361d0;
import androidx.recyclerview.widget.F0;
import com.google.android.gms.measurement.internal.Z;
import com.quizlet.quizletandroid.R;
import java.io.Serializable;
import java.util.ArrayList;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONArray;

/* loaded from: classes2.dex */
public final class v extends AbstractC1361d0 {
    public final /* synthetic */ int a = 1;
    public final Object b;
    public final Serializable c;

    public v(JSONArray jSONArray, String str) {
        this.b = jSONArray;
        this.c = str;
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final int getItemCount() {
        switch (this.a) {
            case 0:
                return ((JSONArray) this.b).length();
            default:
                ArrayList arrayList = (ArrayList) this.c;
                if (arrayList.size() > 7) {
                    return 7;
                }
                return arrayList.size();
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final void onBindViewHolder(F0 f0, int i) {
        switch (this.a) {
            case 0:
                String str = (String) this.c;
                u uVar = (u) f0;
                uVar.setIsRecyclable(false);
                TextView textView = uVar.a;
                try {
                    textView.setText(((JSONArray) this.b).getJSONObject(uVar.getAdapterPosition()).getString("name"));
                    textView.setTextColor(Color.parseColor(str));
                    for (Drawable drawable : textView.getCompoundDrawables()) {
                        if (drawable != null) {
                            drawable.setColorFilter(new PorterDuffColorFilter(Color.parseColor(str), PorterDuff.Mode.SRC_IN));
                        }
                    }
                    break;
                } catch (Exception e) {
                    Z.n("error while rendering purpose items in Vendor detail screen ", e, "OneTrust", 6);
                    return;
                }
            default:
                com.quizlet.quizletandroid.ui.preview.viewholder.a viewHolder = (com.quizlet.quizletandroid.ui.preview.viewholder.a) f0;
                Intrinsics.checkNotNullParameter(viewHolder, "viewHolder");
                Object obj = ((ArrayList) this.c).get(i);
                Intrinsics.checkNotNullExpressionValue(obj, "get(...)");
                viewHolder.c((com.quizlet.quizletandroid.ui.preview.dataclass.c) obj);
                break;
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final F0 onCreateViewHolder(ViewGroup parent, int i) {
        switch (this.a) {
            case 0:
                return new u(Z.c(parent, R.layout.ot_tv_vendor_details_purpose_item, parent, false));
            default:
                Intrinsics.checkNotNullParameter(parent, "parent");
                LayoutInflater layoutInflaterFrom = LayoutInflater.from(parent.getContext());
                int i2 = com.quizlet.quizletandroid.ui.preview.viewholder.a.e;
                View viewInflate = layoutInflaterFrom.inflate(R.layout.search_set_preview_term_view_holder, parent, false);
                Intrinsics.d(viewInflate);
                return new com.quizlet.quizletandroid.ui.preview.viewholder.a(viewInflate, (com.quizlet.qutils.image.loading.a) this.b);
        }
    }

    public v(com.quizlet.qutils.image.loading.a imageLoader) {
        Intrinsics.checkNotNullParameter(imageLoader, "imageLoader");
        this.b = imageLoader;
        this.c = new ArrayList();
    }
}

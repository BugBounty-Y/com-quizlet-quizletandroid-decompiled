package com.onetrust.otpublishers.headless.UI.adapter;

import android.content.Context;
import android.graphics.Color;
import android.graphics.drawable.Drawable;
import android.view.View;
import androidx.appcompat.widget.SwitchCompat;
import androidx.recyclerview.widget.AbstractC1361d0;
import androidx.recyclerview.widget.F0;
import com.google.android.gms.measurement.internal.Z;
import com.quizlet.quizletandroid.R;
import java.util.ArrayList;
import org.json.JSONException;
import org.json.JSONObject;

/* renamed from: com.onetrust.otpublishers.headless.UI.adapter.e, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class ViewOnClickListenerC4049e implements View.OnClickListener {
    public final /* synthetic */ int a = 0;
    public final /* synthetic */ int b;
    public final /* synthetic */ AbstractC1361d0 c;
    public final /* synthetic */ Object d;
    public final /* synthetic */ F0 e;

    public /* synthetic */ ViewOnClickListenerC4049e(int i, C4052h c4052h, C4053i c4053i, JSONObject jSONObject) {
        this.c = c4053i;
        this.d = jSONObject;
        this.b = i;
        this.e = c4052h;
    }

    @Override // android.view.View.OnClickListener
    public final void onClick(View view) {
        Drawable thumbDrawable;
        int color;
        Drawable thumbDrawable2;
        int color2;
        switch (this.a) {
            case 0:
                JSONObject jSONObject = (JSONObject) this.d;
                int i = this.b;
                C4052h c4052h = (C4052h) this.e;
                C4053i c4053i = (C4053i) this.c;
                c4053i.getClass();
                try {
                    c4053i.j(jSONObject.getString("Parent"), c4053i.c.getJSONObject(i).optString("CustomGroupId", ""), c4052h.j.isChecked(), true);
                    break;
                } catch (JSONException e) {
                    Z.p("Error while updating parent status ", e, "OTPCDetailsAdapter", 6);
                    return;
                }
            default:
                com.onetrust.otpublishers.headless.UI.TVUI.adapter.l lVar = (com.onetrust.otpublishers.headless.UI.TVUI.adapter.l) this.c;
                lVar.getClass();
                com.onetrust.otpublishers.headless.UI.DataModels.c cVar = (com.onetrust.otpublishers.headless.UI.DataModels.c) this.d;
                String str = cVar.a;
                w wVar = (w) this.e;
                ((com.onetrust.otpublishers.headless.Internal.Helper.k) lVar.h).j(str, wVar.c.isChecked());
                SwitchCompat switchCompat = wVar.c;
                boolean zIsChecked = switchCompat.isChecked();
                int i2 = this.b;
                ArrayList arrayList = (ArrayList) lVar.g;
                com.onetrust.otpublishers.headless.UI.UIProperty.e eVar = (com.onetrust.otpublishers.headless.UI.UIProperty.e) lVar.i;
                Context context = lVar.c;
                if (zIsChecked) {
                    switchCompat.getTrackDrawable().setTint(context.getColor(R.color.light_greyOT));
                    if (com.onetrust.otpublishers.headless.Internal.a.j(eVar.c)) {
                        thumbDrawable2 = switchCompat.getThumbDrawable();
                        color2 = context.getColor(R.color.colorPrimaryOT);
                    } else {
                        thumbDrawable2 = switchCompat.getThumbDrawable();
                        color2 = Color.parseColor(eVar.c);
                    }
                    thumbDrawable2.setTint(color2);
                    ((com.onetrust.otpublishers.headless.UI.DataModels.c) arrayList.get(i2)).k = "ACTIVE";
                    lVar.g(wVar, cVar, true);
                    break;
                } else {
                    switchCompat.getTrackDrawable().setTint(context.getColor(R.color.light_greyOT));
                    if (com.onetrust.otpublishers.headless.Internal.a.j(eVar.d)) {
                        thumbDrawable = switchCompat.getThumbDrawable();
                        color = context.getColor(R.color.contentTextColorOT);
                    } else {
                        thumbDrawable = switchCompat.getThumbDrawable();
                        color = Color.parseColor(eVar.d);
                    }
                    thumbDrawable.setTint(color);
                    ((com.onetrust.otpublishers.headless.UI.DataModels.c) arrayList.get(i2)).k = "OPT_OUT";
                    lVar.g(wVar, cVar, false);
                    ArrayList arrayList2 = cVar.i;
                    for (int i3 = 0; i3 < arrayList2.size(); i3++) {
                        ArrayList arrayList3 = ((com.onetrust.otpublishers.headless.UI.DataModels.e) arrayList2.get(i3)).b;
                        for (int i4 = 0; i4 < arrayList3.size(); i4++) {
                            ((com.onetrust.otpublishers.headless.UI.DataModels.d) arrayList3.get(i4)).h = "OPT_OUT";
                        }
                    }
                    ArrayList arrayList4 = cVar.j;
                    for (int i5 = 0; i5 < arrayList4.size(); i5++) {
                        ArrayList arrayList5 = ((com.onetrust.otpublishers.headless.UI.DataModels.b) arrayList4.get(i5)).f;
                        for (int i6 = 0; i6 < arrayList5.size(); i6++) {
                            ((com.onetrust.otpublishers.headless.UI.DataModels.d) arrayList5.get(i6)).h = "OPT_OUT";
                        }
                    }
                    break;
                }
        }
    }

    public /* synthetic */ ViewOnClickListenerC4049e(com.onetrust.otpublishers.headless.UI.TVUI.adapter.l lVar, com.onetrust.otpublishers.headless.UI.DataModels.c cVar, w wVar, int i) {
        this.c = lVar;
        this.d = cVar;
        this.e = wVar;
        this.b = i;
    }
}

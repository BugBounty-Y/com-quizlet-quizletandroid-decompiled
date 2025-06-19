package com.onetrust.otpublishers.headless.UI.TVUI.adapter;

import android.graphics.Color;
import android.view.View;
import android.widget.LinearLayout;
import androidx.camera.camera2.internal.c0;
import androidx.recyclerview.widget.AbstractC1361d0;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final /* synthetic */ class f implements View.OnFocusChangeListener {
    public final /* synthetic */ int a;
    public final /* synthetic */ AbstractC1361d0 b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;
    public final /* synthetic */ Object e;

    public /* synthetic */ f(AbstractC1361d0 abstractC1361d0, Object obj, Object obj2, Object obj3, int i) {
        this.a = i;
        this.b = abstractC1361d0;
        this.c = obj;
        this.d = obj2;
        this.e = obj3;
    }

    @Override // android.view.View.OnFocusChangeListener
    public final void onFocusChange(View view, boolean z) {
        switch (this.a) {
            case 0:
                i iVar = (i) this.b;
                h hVar = (h) this.d;
                c0 c0Var = (c0) this.e;
                if (!z) {
                    hVar.c.setBackgroundColor(Color.parseColor((String) c0Var.b));
                    hVar.a.setTextColor(Color.parseColor((String) c0Var.c));
                    hVar.b.setTextColor(Color.parseColor((String) c0Var.c));
                    break;
                } else {
                    int adapterPosition = hVar.getAdapterPosition();
                    JSONObject jSONObject = (JSONObject) this.c;
                    com.onetrust.otpublishers.headless.UI.TVUI.fragments.k kVar = iVar.a;
                    kVar.a(jSONObject);
                    if (adapterPosition != -1) {
                        i iVar2 = kVar.s;
                        if (adapterPosition != iVar2.d) {
                            iVar2.d = adapterPosition;
                            kVar.t = false;
                        }
                    }
                    hVar.c.setBackgroundColor(Color.parseColor((String) c0Var.d));
                    hVar.a.setTextColor(Color.parseColor((String) c0Var.e));
                    hVar.b.setTextColor(Color.parseColor((String) c0Var.e));
                    break;
                }
            case 1:
                p pVar = (p) this.b;
                pVar.getClass();
                o oVar = (o) this.c;
                if (!z) {
                    oVar.c.setBackgroundColor(Color.parseColor((String) this.e));
                    String str = (String) pVar.c;
                    oVar.a.setTextColor(Color.parseColor(str));
                    p.d(oVar.b, Color.parseColor(str));
                    oVar.d.setCardElevation(1.0f);
                    break;
                } else {
                    LinearLayout linearLayout = oVar.c;
                    com.onetrust.otpublishers.headless.UI.TVUI.datautils.c cVar = (com.onetrust.otpublishers.headless.UI.TVUI.datautils.c) this.d;
                    linearLayout.setBackgroundColor(Color.parseColor((String) cVar.j.y.l));
                    oVar.a.setTextColor(Color.parseColor((String) cVar.j.y.m));
                    p.d(oVar.b, Color.parseColor((String) cVar.j.y.m));
                    oVar.d.setCardElevation(6.0f);
                    break;
                }
            default:
                p pVar2 = (p) this.b;
                pVar2.getClass();
                t tVar = (t) this.c;
                if (!z) {
                    tVar.c.setBackgroundColor(Color.parseColor((String) this.e));
                    String str2 = (String) pVar2.c;
                    tVar.a.setTextColor(Color.parseColor(str2));
                    p.g(tVar.b, Color.parseColor(str2));
                    tVar.d.setCardElevation(1.0f);
                    break;
                } else {
                    LinearLayout linearLayout2 = tVar.c;
                    com.onetrust.otpublishers.headless.UI.TVUI.datautils.c cVar2 = (com.onetrust.otpublishers.headless.UI.TVUI.datautils.c) this.d;
                    linearLayout2.setBackgroundColor(Color.parseColor((String) cVar2.j.y.l));
                    tVar.a.setTextColor(Color.parseColor((String) cVar2.j.y.m));
                    p.g(tVar.b, Color.parseColor((String) cVar2.j.y.m));
                    tVar.d.setCardElevation(6.0f);
                    break;
                }
        }
    }
}

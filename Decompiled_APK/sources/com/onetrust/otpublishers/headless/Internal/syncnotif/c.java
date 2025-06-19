package com.onetrust.otpublishers.headless.Internal.syncnotif;

import android.graphics.Color;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.ImageView;
import androidx.camera.camera2.internal.c0;
import androidx.camera.camera2.internal.compat.workaround.e;
import androidx.constraintlayout.motion.widget.n;
import com.google.android.gms.internal.ads.Q1;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.onetrust.otpublishers.headless.Public.Keys.OTFragmentTags;
import com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK;
import com.onetrust.otpublishers.headless.UI.TVUI.adapter.A;
import com.onetrust.otpublishers.headless.UI.TVUI.adapter.B;
import com.onetrust.otpublishers.headless.UI.TVUI.adapter.C4044b;
import com.onetrust.otpublishers.headless.UI.TVUI.adapter.k;
import com.onetrust.otpublishers.headless.UI.TVUI.adapter.l;
import com.onetrust.otpublishers.headless.UI.TVUI.adapter.q;
import com.onetrust.otpublishers.headless.UI.TVUI.adapter.r;
import com.onetrust.otpublishers.headless.UI.TVUI.fragments.s;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final /* synthetic */ class c implements View.OnFocusChangeListener {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;

    public /* synthetic */ c(Object obj, Object obj2, Object obj3, int i) {
        this.a = i;
        this.d = obj;
        this.b = obj2;
        this.c = obj3;
    }

    @Override // android.view.View.OnFocusChangeListener
    public final void onFocusChange(View view, boolean z) {
        switch (this.a) {
            case 0:
                Button button = (Button) this.d;
                if (!z) {
                    OTLogger.c("SyncNotification", 3, "focus: " + z);
                    e.d(button, (JSONObject) ((Q1) this.c).e);
                    break;
                } else {
                    OTLogger.c("SyncNotification", 3, "focus: " + z);
                    Drawable background = button.getBackground();
                    n nVar = (n) this.b;
                    background.setTint(Color.parseColor((String) nVar.l));
                    button.setTextColor(Color.parseColor((String) nVar.m));
                    break;
                }
            case 1:
                ImageView imageView = (ImageView) this.d;
                if (!z) {
                    e.i((Q1) this.c, imageView);
                    break;
                } else {
                    Drawable background2 = imageView.getBackground();
                    n nVar2 = (n) this.b;
                    background2.setTint(Color.parseColor((String) nVar2.l));
                    imageView.getDrawable().setTint(Color.parseColor((String) nVar2.m));
                    break;
                }
            case 2:
                com.onetrust.otpublishers.headless.UI.TVUI.adapter.c cVar = (com.onetrust.otpublishers.headless.UI.TVUI.adapter.c) this.d;
                com.onetrust.otpublishers.headless.UI.TVUI.datautils.c cVar2 = cVar.d;
                C4044b c4044b = (C4044b) this.c;
                if (!z) {
                    c4044b.a.setTextColor(Color.parseColor((String) cVar2.j.B.c));
                    c4044b.c.setBackgroundColor(Color.parseColor((String) cVar2.j.B.b));
                    break;
                } else {
                    s sVar = cVar.a;
                    sVar.I = false;
                    sVar.L((String) this.b);
                    c4044b.a.setTextColor(Color.parseColor((String) cVar2.j.B.e));
                    c4044b.c.setBackgroundColor(Color.parseColor((String) cVar2.j.B.d));
                    if (c4044b.getAdapterPosition() != -1 && c4044b.getAdapterPosition() != cVar.e) {
                        cVar.e = c4044b.getAdapterPosition();
                        break;
                    }
                }
                break;
            case 3:
                com.onetrust.otpublishers.headless.UI.TVUI.datautils.c cVar3 = (com.onetrust.otpublishers.headless.UI.TVUI.datautils.c) ((l) this.d).i;
                k kVar = (k) this.b;
                if (!z) {
                    l.d(kVar, cVar3.l(), (String) this.c);
                    break;
                } else {
                    c0 c0Var = cVar3.j.B;
                    l.d(kVar, (String) c0Var.e, (String) c0Var.d);
                    break;
                }
            case 4:
                r rVar = (r) this.d;
                com.onetrust.otpublishers.headless.UI.TVUI.datautils.c cVar4 = rVar.c;
                q qVar = (q) this.c;
                if (!z) {
                    qVar.a.setTextColor(Color.parseColor((String) cVar4.j.B.c));
                    qVar.b.setBackgroundColor(Color.parseColor((String) cVar4.j.B.b));
                    break;
                } else {
                    com.onetrust.otpublishers.headless.UI.TVUI.fragments.n nVar3 = rVar.a;
                    nVar3.B = false;
                    com.onetrust.otpublishers.headless.Internal.Event.a aVar = nVar3.A;
                    OTPublishersHeadlessSDK oTPublishersHeadlessSDK = nVar3.z;
                    com.onetrust.otpublishers.headless.UI.TVUI.fragments.l lVar = new com.onetrust.otpublishers.headless.UI.TVUI.fragments.l();
                    Bundle bundle = new Bundle();
                    bundle.putString(OTFragmentTags.FRAGMENT_TAG, OTFragmentTags.OT_SDK_DETAIL_FRAGMENT);
                    lVar.setArguments(bundle);
                    lVar.p = nVar3;
                    lVar.l = (JSONObject) this.b;
                    lVar.u = aVar;
                    lVar.v = oTPublishersHeadlessSDK;
                    nVar3.o = lVar;
                    nVar3.I(lVar);
                    qVar.a.setTextColor(Color.parseColor((String) cVar4.j.B.e));
                    qVar.b.setBackgroundColor(Color.parseColor((String) cVar4.j.B.d));
                    if (qVar.getAdapterPosition() != -1 && qVar.getAdapterPosition() != rVar.e) {
                        rVar.e = qVar.getAdapterPosition();
                        break;
                    }
                }
                break;
            default:
                B b = (B) this.d;
                com.onetrust.otpublishers.headless.UI.TVUI.datautils.c cVar5 = b.d;
                A a = (A) this.c;
                if (!z) {
                    a.a.setTextColor(Color.parseColor((String) cVar5.j.B.c));
                    a.c.setBackgroundColor(Color.parseColor((String) cVar5.j.B.b));
                    break;
                } else {
                    s sVar2 = b.a;
                    sVar2.I = false;
                    sVar2.L((String) this.b);
                    a.a.setTextColor(Color.parseColor((String) cVar5.j.B.e));
                    a.c.setBackgroundColor(Color.parseColor((String) cVar5.j.B.d));
                    if (a.getAdapterPosition() != -1 && a.getAdapterPosition() != b.g) {
                        b.g = a.getAdapterPosition();
                        break;
                    }
                }
                break;
        }
    }
}

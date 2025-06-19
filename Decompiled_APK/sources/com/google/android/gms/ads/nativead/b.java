package com.google.android.gms.ads.nativead;

import android.content.Context;
import android.os.RemoteException;
import android.widget.FrameLayout;
import android.widget.ImageView;
import androidx.annotation.NonNull;
import androidx.webkit.internal.p;
import com.google.android.gms.ads.internal.client.F0;
import com.google.android.gms.ads.internal.util.client.i;
import com.google.android.gms.ads.m;
import com.google.android.gms.internal.ads.C8;
import com.google.android.gms.internal.ads.J8;

/* loaded from: classes2.dex */
public class b extends FrameLayout {
    public m a;
    public boolean b;
    public ImageView.ScaleType c;
    public boolean d;
    public p e;
    public com.airbnb.lottie.network.c f;

    public b(@NonNull Context context) {
        super(context);
    }

    public m getMediaContent() {
        return this.a;
    }

    public void setImageScaleType(@NonNull ImageView.ScaleType scaleType) {
        C8 c8;
        this.d = true;
        this.c = scaleType;
        com.airbnb.lottie.network.c cVar = this.f;
        if (cVar == null || (c8 = ((NativeAdView) cVar.b).b) == null || scaleType == null) {
            return;
        }
        try {
            c8.m2(new com.google.android.gms.dynamic.b(scaleType));
        } catch (RemoteException e) {
            i.f("Unable to call setMediaViewImageScaleType on delegate", e);
        }
    }

    public void setMediaContent(m mVar) {
        boolean zT;
        boolean zW;
        this.b = true;
        this.a = mVar;
        p pVar = this.e;
        if (pVar != null) {
            NativeAdView.b((NativeAdView) pVar.b, mVar);
        }
        if (mVar == null) {
            return;
        }
        try {
            J8 j8 = ((F0) mVar).c;
            if (j8 != null) {
                if (!((F0) mVar).b()) {
                    try {
                        zT = ((F0) mVar).a.t();
                    } catch (RemoteException e) {
                        i.f("", e);
                        zT = false;
                    }
                    if (zT) {
                        zW = j8.W(new com.google.android.gms.dynamic.b(this));
                    }
                    removeAllViews();
                }
                zW = j8.U(new com.google.android.gms.dynamic.b(this));
                if (zW) {
                    return;
                }
                removeAllViews();
            }
        } catch (RemoteException e2) {
            removeAllViews();
            i.f("", e2);
        }
    }
}

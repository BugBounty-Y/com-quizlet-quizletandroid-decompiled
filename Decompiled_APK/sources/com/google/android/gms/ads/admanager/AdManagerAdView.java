package com.google.android.gms.ads.admanager;

import android.content.Context;
import android.os.RemoteException;
import android.util.AttributeSet;
import android.view.View;
import androidx.annotation.NonNull;
import com.google.android.gms.ads.h;
import com.google.android.gms.ads.internal.client.A0;
import com.google.android.gms.ads.internal.client.K;
import com.google.android.gms.ads.internal.client.r;
import com.google.android.gms.ads.internal.client.zzfw;
import com.google.android.gms.ads.internal.util.client.i;
import com.google.android.gms.ads.k;
import com.google.android.gms.ads.s;
import com.google.android.gms.ads.t;
import com.google.android.gms.common.internal.u;
import com.google.android.gms.internal.ads.AbstractC2773w7;
import com.google.android.gms.internal.ads.C1744Ob;
import com.google.android.gms.internal.ads.U7;
import com.google.common.util.concurrent.d;

/* loaded from: classes2.dex */
public final class AdManagerAdView extends k {
    public AdManagerAdView(@NonNull Context context) {
        super(context);
        u.i(context, "Context cannot be null");
    }

    public static /* synthetic */ void zza(@NonNull AdManagerAdView adManagerAdView, @NonNull AdManagerAdRequest adManagerAdRequest) {
        try {
            adManagerAdView.zza.b(adManagerAdRequest.zza());
        } catch (IllegalStateException e) {
            C1744Ob.a(adManagerAdView.getContext()).d("AdManagerAdView.loadAd", e);
        }
    }

    public h[] getAdSizes() {
        return this.zza.h;
    }

    public a getAppEventListener() {
        return this.zza.i;
    }

    @NonNull
    public s getVideoController() {
        return this.zza.d;
    }

    public t getVideoOptions() {
        return this.zza.k;
    }

    public void loadAd(@NonNull AdManagerAdRequest adManagerAdRequest) {
        u.d("#008 Must be called on the main UI thread.");
        AbstractC2773w7.a(getContext());
        if (((Boolean) U7.f.o()).booleanValue()) {
            if (((Boolean) r.d.c.a(AbstractC2773w7.hb)).booleanValue()) {
                com.google.android.gms.ads.internal.util.client.a.b.execute(new d(13, this, adManagerAdRequest));
                return;
            }
        }
        this.zza.b(adManagerAdRequest.zza());
    }

    public void recordManualImpression() {
        A0 a0 = this.zza;
        if (a0.c.getAndSet(true)) {
            return;
        }
        try {
            K k = a0.j;
            if (k != null) {
                k.j0();
            }
        } catch (RemoteException e) {
            i.j("#007 Could not call remote method.", e);
        }
    }

    public void setAdSizes(@NonNull h... hVarArr) {
        if (hVarArr == null || hVarArr.length <= 0) {
            throw new IllegalArgumentException("The supported ad sizes must contain at least one valid ad size.");
        }
        this.zza.d(hVarArr);
    }

    public void setAppEventListener(a aVar) {
        this.zza.e(aVar);
    }

    public void setManualImpressionsEnabled(boolean z) {
        A0 a0 = this.zza;
        a0.n = z;
        try {
            K k = a0.j;
            if (k != null) {
                k.X3(z);
            }
        } catch (RemoteException e) {
            i.j("#007 Could not call remote method.", e);
        }
    }

    public void setVideoOptions(@NonNull t tVar) {
        A0 a0 = this.zza;
        a0.k = tVar;
        try {
            K k = a0.j;
            if (k != null) {
                k.W1(tVar == null ? null : new zzfw(tVar));
            }
        } catch (RemoteException e) {
            i.j("#007 Could not call remote method.", e);
        }
    }

    public final boolean zzb(K k) {
        A0 a0 = this.zza;
        a0.getClass();
        try {
            com.google.android.gms.dynamic.a aVarM = k.m();
            if (aVarM == null || ((View) com.google.android.gms.dynamic.b.I3(aVarM)).getParent() != null) {
                return false;
            }
            a0.m.addView((View) com.google.android.gms.dynamic.b.I3(aVarM));
            a0.j = k;
            return true;
        } catch (RemoteException e) {
            i.j("#007 Could not call remote method.", e);
            return false;
        }
    }

    public AdManagerAdView(@NonNull Context context, @NonNull AttributeSet attributeSet) {
        super(context, attributeSet);
        u.i(context, "Context cannot be null");
    }

    public AdManagerAdView(@NonNull Context context, @NonNull AttributeSet attributeSet, int i) {
        super(context, attributeSet, i);
        u.i(context, "Context cannot be null");
    }
}

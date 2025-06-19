package com.google.android.gms.ads;

import android.content.Context;
import android.os.RemoteException;
import android.util.AttributeSet;
import android.util.DisplayMetrics;
import android.view.View;
import android.view.ViewGroup;
import androidx.annotation.NonNull;
import com.google.android.gms.ads.internal.client.A0;
import com.google.android.gms.ads.internal.client.C1614q;
import com.google.android.gms.ads.internal.client.InterfaceC1582a;
import com.google.android.gms.ads.internal.client.K;
import com.google.android.gms.ads.internal.client.N0;
import com.google.android.gms.ads.internal.client.s0;
import com.google.android.gms.ads.internal.client.z0;
import com.google.android.gms.ads.internal.client.zzr;
import com.google.android.gms.internal.ads.AbstractC2773w7;
import com.google.android.gms.internal.ads.U7;
import org.checkerframework.checker.initialization.qual.NotOnlyInitialized;

/* loaded from: classes2.dex */
public abstract class k extends ViewGroup {

    @NotOnlyInitialized
    protected final A0 zza;

    public k(Context context) {
        super(context);
        this.zza = new A0(this, null, false);
    }

    public void destroy() {
        AbstractC2773w7.a(getContext());
        if (((Boolean) U7.e.o()).booleanValue()) {
            if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.eb)).booleanValue()) {
                com.google.android.gms.ads.internal.util.client.a.b.execute(new u(this, 1));
                return;
            }
        }
        A0 a0 = this.zza;
        a0.getClass();
        try {
            K k = a0.j;
            if (k != null) {
                k.y();
            }
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
        }
    }

    @NonNull
    public d getAdListener() {
        return this.zza.g;
    }

    public h getAdSize() {
        zzr zzrVarH;
        A0 a0 = this.zza;
        a0.getClass();
        try {
            K k = a0.j;
            if (k != null && (zzrVarH = k.h()) != null) {
                return new h(zzrVarH.e, zzrVarH.b, zzrVarH.a);
            }
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
        }
        h[] hVarArr = a0.h;
        if (hVarArr != null) {
            return hVarArr[0];
        }
        return null;
    }

    @NonNull
    public String getAdUnitId() {
        K k;
        A0 a0 = this.zza;
        if (a0.l == null && (k = a0.j) != null) {
            try {
                a0.l = k.w();
            } catch (RemoteException e) {
                com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
            }
        }
        return a0.l;
    }

    public n getOnPaidEventListener() {
        this.zza.getClass();
        return null;
    }

    public q getResponseInfo() {
        K k;
        A0 a0 = this.zza;
        a0.getClass();
        try {
            k = a0.j;
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
        }
        s0 s0VarN = k != null ? k.n() : null;
        if (s0VarN != null) {
            return new q(s0VarN);
        }
        return null;
    }

    public boolean isCollapsible() {
        A0 a0 = this.zza;
        a0.getClass();
        try {
            K k = a0.j;
            if (k != null) {
                return k.t3();
            }
            return false;
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
            return false;
        }
    }

    public boolean isLoading() {
        A0 a0 = this.zza;
        a0.getClass();
        try {
            K k = a0.j;
            if (k != null) {
                return k.F3();
            }
            return false;
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
            return false;
        }
    }

    public void loadAd(@NonNull g gVar) {
        com.google.android.gms.common.internal.u.d("#008 Must be called on the main UI thread.");
        AbstractC2773w7.a(getContext());
        if (((Boolean) U7.f.o()).booleanValue()) {
            if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.hb)).booleanValue()) {
                com.google.android.gms.ads.internal.util.client.a.b.execute(new v(0, this, gVar));
                return;
            }
        }
        this.zza.b(gVar.zza);
    }

    @Override // android.view.ViewGroup, android.view.View
    public void onLayout(boolean z, int i, int i2, int i3, int i4) {
        View childAt = getChildAt(0);
        if (childAt == null || childAt.getVisibility() == 8) {
            return;
        }
        int measuredWidth = childAt.getMeasuredWidth();
        int measuredHeight = childAt.getMeasuredHeight();
        int i5 = ((i3 - i) - measuredWidth) / 2;
        int i6 = ((i4 - i2) - measuredHeight) / 2;
        childAt.layout(i5, i6, measuredWidth + i5, measuredHeight + i6);
    }

    @Override // android.view.View
    public void onMeasure(int i, int i2) {
        h adSize;
        int measuredHeight;
        int iN;
        int iN2;
        int measuredWidth = 0;
        View childAt = getChildAt(0);
        if (childAt == null || childAt.getVisibility() == 8) {
            try {
                adSize = getAdSize();
            } catch (NullPointerException e) {
                com.google.android.gms.ads.internal.util.client.i.f("Unable to retrieve ad size.", e);
                adSize = null;
            }
            if (adSize != null) {
                Context context = getContext();
                int i3 = adSize.a;
                if (i3 == -3) {
                    iN = -1;
                } else if (i3 != -1) {
                    com.google.android.gms.ads.internal.util.client.c cVar = C1614q.f.a;
                    iN = com.google.android.gms.ads.internal.util.client.c.n(context, i3);
                } else {
                    iN = context.getResources().getDisplayMetrics().widthPixels;
                }
                int i4 = adSize.b;
                if (i4 == -4 || i4 == -3) {
                    iN2 = -1;
                } else if (i4 != -2) {
                    com.google.android.gms.ads.internal.util.client.c cVar2 = C1614q.f.a;
                    iN2 = com.google.android.gms.ads.internal.util.client.c.n(context, i4);
                } else {
                    DisplayMetrics displayMetrics = context.getResources().getDisplayMetrics();
                    float f = displayMetrics.heightPixels;
                    float f2 = displayMetrics.density;
                    int i5 = (int) (f / f2);
                    iN2 = (int) ((i5 <= 400 ? 32 : i5 <= 720 ? 50 : 90) * f2);
                }
                measuredHeight = iN2;
                measuredWidth = iN;
            } else {
                measuredHeight = 0;
            }
        } else {
            measureChild(childAt, i, i2);
            measuredWidth = childAt.getMeasuredWidth();
            measuredHeight = childAt.getMeasuredHeight();
        }
        setMeasuredDimension(View.resolveSize(Math.max(measuredWidth, getSuggestedMinimumWidth()), i), View.resolveSize(Math.max(measuredHeight, getSuggestedMinimumHeight()), i2));
    }

    public void pause() {
        AbstractC2773w7.a(getContext());
        if (((Boolean) U7.g.o()).booleanValue()) {
            if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.fb)).booleanValue()) {
                com.google.android.gms.ads.internal.util.client.a.b.execute(new u(this, 2));
                return;
            }
        }
        A0 a0 = this.zza;
        a0.getClass();
        try {
            K k = a0.j;
            if (k != null) {
                k.P();
            }
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
        }
    }

    public void resume() {
        AbstractC2773w7.a(getContext());
        if (((Boolean) U7.h.o()).booleanValue()) {
            if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.db)).booleanValue()) {
                com.google.android.gms.ads.internal.util.client.a.b.execute(new u(this, 0));
                return;
            }
        }
        A0 a0 = this.zza;
        a0.getClass();
        try {
            K k = a0.j;
            if (k != null) {
                k.K();
            }
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    public void setAdListener(@NonNull d dVar) {
        A0 a0 = this.zza;
        a0.g = dVar;
        z0 z0Var = a0.e;
        synchronized (z0Var.b) {
            z0Var.c = dVar;
        }
        if (dVar == 0) {
            a0.c(null);
            return;
        }
        if (dVar instanceof InterfaceC1582a) {
            a0.c((InterfaceC1582a) dVar);
        }
        if (dVar instanceof com.google.android.gms.ads.admanager.a) {
            a0.e((com.google.android.gms.ads.admanager.a) dVar);
        }
    }

    public void setAdSize(@NonNull h hVar) {
        h[] hVarArr = {hVar};
        A0 a0 = this.zza;
        if (a0.h != null) {
            throw new IllegalStateException("The ad size can only be set once on AdView.");
        }
        a0.d(hVarArr);
    }

    public void setAdUnitId(@NonNull String str) {
        A0 a0 = this.zza;
        if (a0.l != null) {
            throw new IllegalStateException("The ad unit ID can only be set once on AdView.");
        }
        a0.l = str;
    }

    public void setOnPaidEventListener(n nVar) {
        A0 a0 = this.zza;
        a0.getClass();
        try {
            K k = a0.j;
            if (k != null) {
                k.j3(new N0());
            }
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
        }
    }

    public k(Context context, AttributeSet attributeSet, int i) {
        super(context, attributeSet, i);
        this.zza = new A0(this, attributeSet, true);
    }

    public k(Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
        this.zza = new A0(this, attributeSet, true);
    }
}

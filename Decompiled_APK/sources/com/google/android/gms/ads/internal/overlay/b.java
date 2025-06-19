package com.google.android.gms.ads.internal.overlay;

import android.app.Activity;
import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import androidx.appcompat.app.J;
import com.google.android.gms.ads.internal.client.InterfaceC1582a;
import com.google.android.gms.ads.internal.client.r;
import com.google.android.gms.ads.internal.util.A;
import com.google.android.gms.ads.internal.util.F;
import com.google.android.gms.internal.ads.AbstractBinderC1666Bb;
import com.google.android.gms.internal.ads.AbstractC2773w7;
import com.google.android.gms.internal.ads.C2601s7;
import com.google.android.gms.internal.ads.InterfaceC2447oi;
import com.google.android.gms.internal.ads.L5;
import com.google.android.gms.internal.ads.SharedPreferencesOnSharedPreferenceChangeListenerC2687u7;

/* loaded from: classes2.dex */
public final class b extends AbstractBinderC1666Bb implements L5 {
    public final AdOverlayInfoParcel b;
    public final Activity c;
    public final boolean g;
    public boolean d = false;
    public boolean e = false;
    public boolean f = false;
    public boolean h = false;
    public boolean i = false;

    public b(Activity activity, AdOverlayInfoParcel adOverlayInfoParcel) {
        zzc zzcVar;
        boolean z = false;
        this.b = adOverlayInfoParcel;
        this.c = activity;
        C2601s7 c2601s7 = AbstractC2773w7.K4;
        r rVar = r.d;
        boolean zBooleanValue = ((Boolean) rVar.c.a(c2601s7)).booleanValue();
        SharedPreferencesOnSharedPreferenceChangeListenerC2687u7 sharedPreferencesOnSharedPreferenceChangeListenerC2687u7 = rVar.c;
        if ((zBooleanValue || ((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.L4)).booleanValue() || ((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.P4)).booleanValue()) && (zzcVar = adOverlayInfoParcel.a) != null && zzcVar.j && Build.MANUFACTURER.matches((String) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.N4)) && Build.MODEL.matches((String) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.O4))) {
            z = true;
        }
        this.g = z;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1672Cb
    public final void B2(Bundle bundle) {
        bundle.putBoolean("com.google.android.gms.ads.internal.overlay.hasResumed", this.d);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1672Cb
    public final void H1(int i, String[] strArr, int[] iArr) {
    }

    @Override // com.google.android.gms.internal.ads.L5
    public final void V(boolean z) {
        if (!z) {
            this.i = true;
        } else if (this.i) {
            com.google.android.gms.ads.internal.util.client.i.d("Foregrounded: finishing activity from LauncherOverlay");
            this.c.finish();
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1672Cb
    public final void c() {
        if (this.c.isFinishing()) {
            e4();
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1672Cb
    public final void d() {
        j jVar = this.b.c;
        if (jVar != null) {
            jVar.L2();
        }
    }

    public final synchronized void e4() {
        try {
            if (!this.e) {
                j jVar = this.b.c;
                if (jVar != null) {
                    jVar.X(4);
                }
                this.e = true;
                if (this.g) {
                    if (((Boolean) r.d.c.a(AbstractC2773w7.P4)).booleanValue()) {
                        com.google.android.gms.ads.internal.j.C.g.o(this);
                    }
                }
            }
        } catch (Throwable th) {
            throw th;
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1672Cb
    public final void l() {
        if (this.c.isFinishing()) {
            e4();
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1672Cb
    public final void m1(int i, int i2, Intent intent) {
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1672Cb
    public final void p() {
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1672Cb
    public final void p2(Bundle bundle) {
        j jVar;
        C2601s7 c2601s7 = AbstractC2773w7.S8;
        r rVar = r.d;
        boolean zBooleanValue = ((Boolean) rVar.c.a(c2601s7)).booleanValue();
        Activity activity = this.c;
        if (zBooleanValue && !this.f) {
            activity.requestWindowFeature(1);
        }
        boolean z = false;
        if (bundle != null && bundle.getBoolean("com.google.android.gms.ads.internal.overlay.hasResumed", false)) {
            z = true;
        }
        AdOverlayInfoParcel adOverlayInfoParcel = this.b;
        if (adOverlayInfoParcel == null) {
            activity.finish();
            return;
        }
        if (z) {
            activity.finish();
            return;
        }
        if (bundle == null) {
            InterfaceC1582a interfaceC1582a = adOverlayInfoParcel.b;
            if (interfaceC1582a != null) {
                interfaceC1582a.onAdClicked();
            }
            InterfaceC2447oi interfaceC2447oi = adOverlayInfoParcel.u;
            if (interfaceC2447oi != null) {
                interfaceC2447oi.c0();
            }
            if (activity.getIntent() != null && activity.getIntent().getBooleanExtra("shouldCallOnOverlayOpened", true) && (jVar = adOverlayInfoParcel.c) != null) {
                jVar.I3();
            }
        }
        if (this.g) {
            if (((Boolean) rVar.c.a(AbstractC2773w7.P4)).booleanValue()) {
                com.google.android.gms.ads.internal.j.C.g.l(this);
            }
        }
        com.quizlet.shared.usecase.srs.a aVar = com.google.android.gms.ads.internal.j.C.a;
        zzc zzcVar = adOverlayInfoParcel.a;
        a aVar2 = zzcVar.i;
        c cVar = adOverlayInfoParcel.i;
        Activity activity2 = this.c;
        if (com.quizlet.shared.usecase.srs.a.z(activity2, zzcVar, cVar, aVar2, null, "")) {
            return;
        }
        activity2.finish();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1672Cb
    public final void s() {
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1672Cb
    public final boolean s3() {
        return ((Boolean) r.d.c.a(AbstractC2773w7.L4)).booleanValue() && this.g && this.h;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1672Cb
    public final void v() {
        this.h = false;
        j jVar = this.b.c;
        if (jVar != null) {
            jVar.Y3();
        }
        if (this.c.isFinishing()) {
            e4();
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1672Cb
    public final void v2(com.google.android.gms.dynamic.a aVar) {
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1672Cb
    public final void w() {
        if (this.d) {
            A.l("LauncherOverlay finishing activity");
            this.c.finish();
            return;
        }
        this.d = true;
        this.h = true;
        j jVar = this.b.c;
        if (jVar != null) {
            jVar.v3();
        }
        if (this.g) {
            if (((Boolean) r.d.c.a(AbstractC2773w7.K4)).booleanValue()) {
                F.l.postDelayed(new J(this, 22), ((Integer) r1.c.a(AbstractC2773w7.M4)).intValue());
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1672Cb
    public final void y() {
        this.f = true;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1672Cb
    public final void zzi() {
    }
}

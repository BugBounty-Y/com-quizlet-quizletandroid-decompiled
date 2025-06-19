package com.google.android.gms.internal.ads;

import android.content.Context;
import android.content.Intent;
import android.media.AudioDeviceInfo;
import android.net.Uri;
import android.os.Build;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.provider.Settings;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.facebook.internal.C1549d;
import com.google.android.gms.ads.internal.overlay.AdOverlayInfoParcel;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import com.google.android.gms.ads.internal.zzl;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Objects;
import java.util.WeakHashMap;

/* loaded from: classes2.dex */
public final class Tm implements Ai {
    public boolean a;
    public final Object b;
    public final Object c;
    public final Object d;
    public final Object e;
    public final Object f;
    public Object g;
    public Object h;
    public Object i;
    public Object j;

    public Tm(Context context, VersionInfoParcel versionInfoParcel, C2313ld c2313ld, Vp vp, InterfaceC2529qe interfaceC2529qe, C2023eq c2023eq, boolean z, C2475p9 c2475p9, BinderC2408nm binderC2408nm, Hk hk) {
        this.b = context;
        this.c = versionInfoParcel;
        this.d = c2313ld;
        this.e = vp;
        this.f = interfaceC2529qe;
        this.g = c2023eq;
        this.h = c2475p9;
        this.a = z;
        this.i = binderC2408nm;
        this.j = hk;
    }

    public void a(AudioDeviceInfo audioDeviceInfo) {
        C2883yp c2883yp = (C2883yp) this.h;
        if (Objects.equals(audioDeviceInfo, c2883yp == null ? null : (AudioDeviceInfo) c2883yp.b)) {
            return;
        }
        C2883yp c2883yp2 = audioDeviceInfo != null ? new C2883yp(audioDeviceInfo, 11) : null;
        this.h = c2883yp2;
        b(C2004eE.b((Context) this.b, (Wl) this.i, c2883yp2));
    }

    public void b(C2004eE c2004eE) {
        VF vf;
        if (!this.a || c2004eE.equals((C2004eE) this.g)) {
            return;
        }
        this.g = c2004eE;
        C2608sE c2608sE = (C2608sE) ((C2586rt) this.j).b;
        c2608sE.getClass();
        Looper looperMyLooper = Looper.myLooper();
        Looper looper = c2608sE.T;
        if (looper != looperMyLooper) {
            throw new IllegalStateException(AbstractC0147y.e("Current looper (", looperMyLooper == null ? "null" : looperMyLooper.getThread().getName(), ") is not the playback looper (", looper == null ? "null" : looper.getThread().getName(), ")"));
        }
        C2004eE c2004eE2 = c2608sE.q;
        if (c2004eE2 == null || c2004eE.equals(c2004eE2)) {
            return;
        }
        c2608sE.q = c2004eE;
        Sq sq = c2608sE.l;
        if (sq != null) {
            C2651tE c2651tE = (C2651tE) sq.a;
            synchronized (c2651tE.a) {
                vf = c2651tE.r;
            }
            if (vf != null) {
                synchronized (vf.c) {
                    vf.e.getClass();
                }
            }
        }
    }

    public void c(Runnable runnable) {
        ((Handler) ((Bt) this.c).zza()).post(new RunnableC2286kt(this, runnable, 0));
    }

    @Override // com.google.android.gms.internal.ads.Ai
    public void k(boolean z, Context context, C2058fh c2058fh) {
        float f;
        C1807Ye c1807Ye = (C1807Ye) AbstractC2025es.Q((C2313ld) this.d);
        InterfaceC2529qe interfaceC2529qe = (InterfaceC2529qe) this.f;
        interfaceC2529qe.I0(true);
        C2475p9 c2475p9 = (C2475p9) this.h;
        boolean z2 = this.a;
        boolean z3 = false;
        boolean zA = z2 ? c2475p9.a(false) : false;
        com.google.android.gms.ads.internal.util.F f2 = com.google.android.gms.ads.internal.j.C.c;
        boolean zH = com.google.android.gms.ads.internal.util.F.h((Context) this.b);
        if (z2) {
            synchronized (c2475p9) {
                z3 = c2475p9.b;
            }
        }
        if (z2) {
            synchronized (c2475p9) {
                f = c2475p9.c;
            }
        } else {
            f = DefinitionKt.NO_Float_VALUE;
        }
        float f3 = f;
        Vp vp = (Vp) this.e;
        zzl zzlVar = new zzl(zA, zH, z3, f3, z, vp.O, false);
        if (c2058fh != null) {
            c2058fh.f();
        }
        C2919zi c2919zi = (C2919zi) c1807Ye.W.zzb();
        Yp yp = vp.s;
        assistantMode.utils.studiableMetadata.b.a0(context, new AdOverlayInfoParcel(c2919zi, interfaceC2529qe, vp.Q, (VersionInfoParcel) this.c, vp.B, zzlVar, yp.b, yp.a, ((C2023eq) this.g).f, c2058fh, vp.b() ? (BinderC2408nm) this.i : null, interfaceC2529qe.w()), true, (Hk) this.j);
    }

    @Override // com.google.android.gms.internal.ads.Ai
    /* renamed from: zza */
    public Vp mo17zza() {
        return (Vp) this.e;
    }

    public Tm() {
        this.b = new HashMap();
        this.c = new HashMap();
        this.d = new HashMap();
        this.e = new HashSet();
        this.f = new HashSet();
        this.g = new HashSet();
        this.h = new HashMap();
        this.i = new HashSet();
        this.j = new WeakHashMap();
    }

    public Tm(Context context, C2586rt c2586rt, Wl wl, C2883yp c2883yp) {
        Context applicationContext = context.getApplicationContext();
        this.b = applicationContext;
        this.j = c2586rt;
        this.i = wl;
        this.h = c2883yp;
        String str = Yo.a;
        Looper looperMyLooper = Looper.myLooper();
        Handler handler = new Handler(looperMyLooper == null ? Looper.getMainLooper() : looperMyLooper, null);
        this.c = handler;
        this.d = new C2048fE(this);
        this.e = new C1549d(this, 11);
        C2004eE c2004eE = C2004eE.c;
        String str2 = Build.MANUFACTURER;
        Uri uriFor = (str2.equals("Amazon") || str2.equals("Xiaomi")) ? Settings.Global.getUriFor("external_surround_sound_enabled") : null;
        this.f = uriFor != null ? new C2092gE(this, handler, applicationContext.getContentResolver(), uriFor) : null;
    }

    public Tm(Context context, Gw gw, Intent intent) {
        this.f = new ArrayList();
        this.b = context;
        this.d = gw;
        this.e = "OverlayDisplayService";
        this.g = intent;
        this.c = AbstractC2457os.e(new Is(2));
        this.h = new IBinder.DeathRecipient() { // from class: com.google.android.gms.internal.ads.jt
            @Override // android.os.IBinder.DeathRecipient
            public final void binderDied() {
                Tm tm = this.a;
                ((Gw) tm.d).c("%s : Binder has died.", (String) tm.e);
                ArrayList arrayList = (ArrayList) tm.f;
                synchronized (arrayList) {
                    arrayList.clear();
                }
            }
        };
    }
}

package com.google.android.gms.internal.ads;

import android.content.Context;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;

/* renamed from: com.google.android.gms.internal.ads.nk, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2406nk {
    public final Context a;
    public final P4 b;
    public final J7 c;
    public final VersionInfoParcel d;
    public final androidx.work.impl.model.c e;
    public final C2429o6 f;
    public final Gh g;
    public final BinderC2408nm h;
    public final C2067fq i;
    public final Hk j;

    public C2406nk(Context context, P4 p4, J7 j7, VersionInfoParcel versionInfoParcel, androidx.work.impl.model.c cVar, C2429o6 c2429o6, Gh gh, BinderC2408nm binderC2408nm, C2067fq c2067fq, Hk hk) {
        this.a = context;
        this.b = p4;
        this.c = j7;
        this.d = versionInfoParcel;
        this.e = cVar;
        this.f = c2429o6;
        this.g = gh;
        this.h = binderC2408nm;
        this.i = c2067fq;
        this.j = hk;
    }

    public final InterfaceC2529qe a(com.google.android.gms.ads.internal.client.zzr zzrVar, Vp vp, Xp xp) {
        com.bumptech.glide.load.engine.cache.f fVarA = com.bumptech.glide.load.engine.cache.f.a(zzrVar);
        C2881yn c2881yn = new C2881yn(this, 18);
        VersionInfoParcel versionInfoParcel = this.d;
        androidx.work.impl.model.c cVar = this.e;
        C2067fq c2067fq = this.i;
        Hk hk = this.j;
        Context context = this.a;
        String str = zzrVar.a;
        return L9.g(context, cVar, fVarA, versionInfoParcel, this.b, this.f, this.c, hk, this.h, c2881yn, vp, xp, c2067fq, str, false, false);
    }
}

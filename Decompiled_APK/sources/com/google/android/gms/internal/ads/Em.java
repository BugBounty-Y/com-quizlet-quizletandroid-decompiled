package com.google.android.gms.internal.ads;

import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import java.util.HashMap;
import java.util.HashSet;
import java.util.WeakHashMap;

/* loaded from: classes2.dex */
public final class Em implements Ai {
    public boolean a;
    public final Object b;
    public final Object c;
    public final Object d;
    public final Object e;
    public final Object f;
    public final Object g;
    public final Object h;
    public final Object i;

    public Em() {
        this.b = new HashMap();
        this.c = new HashMap();
        this.d = new HashMap();
        this.e = new HashSet();
        this.f = new HashSet();
        this.g = new HashSet();
        this.h = new HashMap();
        this.i = new WeakHashMap();
    }

    /* JADX WARN: Removed duplicated region for block: B:38:0x0078  */
    @Override // com.google.android.gms.internal.ads.Ai
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void k(boolean r17, android.content.Context r18, com.google.android.gms.internal.ads.C2058fh r19) {
        /*
            Method dump skipped, instructions count: 177
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.Em.k(boolean, android.content.Context, com.google.android.gms.internal.ads.fh):void");
    }

    @Override // com.google.android.gms.internal.ads.Ai
    /* renamed from: zza */
    public Vp mo17zza() {
        return (Vp) this.d;
    }

    public Em(VersionInfoParcel versionInfoParcel, C2313ld c2313ld, Vp vp, InterfaceC2529qe interfaceC2529qe, C2023eq c2023eq, boolean z, C2475p9 c2475p9, BinderC2408nm binderC2408nm, Hk hk) {
        this.b = versionInfoParcel;
        this.c = c2313ld;
        this.d = vp;
        this.e = interfaceC2529qe;
        this.f = c2023eq;
        this.a = z;
        this.g = c2475p9;
        this.h = binderC2408nm;
        this.i = hk;
    }
}

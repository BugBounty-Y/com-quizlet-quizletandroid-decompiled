package com.google.android.gms.internal.ads;

import android.os.Bundle;
import com.google.android.gms.ads.formats.AdManagerAdViewOptions;
import com.google.android.gms.ads.formats.PublisherAdViewOptions;
import com.google.android.gms.ads.internal.client.zzfw;
import com.google.android.gms.ads.internal.client.zzm;
import com.google.android.gms.ads.internal.client.zzx;
import java.util.ArrayList;

/* renamed from: com.google.android.gms.internal.ads.dq, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1979dq {
    public zzm a;
    public com.google.android.gms.ads.internal.client.zzr b;
    public String c;
    public zzfw d;
    public boolean e;
    public ArrayList f;
    public ArrayList g;
    public zzbfv h;
    public zzx i;
    public AdManagerAdViewOptions j;
    public PublisherAdViewOptions k;
    public com.google.android.gms.ads.internal.client.P l;
    public int m = 1;
    public zzbmg n;
    public final com.airbnb.lottie.parser.l o;
    public boolean p;
    public boolean q;
    public Ln r;
    public boolean s;
    public Bundle t;
    public com.google.android.gms.ads.internal.client.T u;

    public C1979dq() {
        com.airbnb.lottie.parser.l lVar = new com.airbnb.lottie.parser.l(5);
        lVar.b = 2;
        this.o = lVar;
        this.p = false;
        this.q = false;
        this.s = false;
    }

    public final C2023eq a() {
        com.google.android.gms.common.internal.u.i(this.c, "ad unit must not be null");
        com.google.android.gms.common.internal.u.i(this.b, "ad size must not be null");
        com.google.android.gms.common.internal.u.i(this.a, "ad request must not be null");
        return new C2023eq(this);
    }
}

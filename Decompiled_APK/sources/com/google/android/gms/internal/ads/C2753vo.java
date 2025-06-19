package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.vo, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2753vo {
    public final com.google.common.util.concurrent.e a;
    public final long b;
    public final com.google.android.gms.common.util.a c;

    public C2753vo(com.google.common.util.concurrent.e eVar, long j, com.google.android.gms.common.util.a aVar) {
        this.a = eVar;
        this.c = aVar;
        this.b = aVar.elapsedRealtime() + j;
    }
}

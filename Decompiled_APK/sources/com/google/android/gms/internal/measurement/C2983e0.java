package com.google.android.gms.internal.measurement;

import android.os.Bundle;

/* renamed from: com.google.android.gms.internal.measurement.e0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2983e0 extends AbstractRunnableC2988f0 {
    public final /* synthetic */ Long e;
    public final /* synthetic */ String f;
    public final /* synthetic */ String g;
    public final /* synthetic */ Bundle h;
    public final /* synthetic */ boolean i;
    public final /* synthetic */ boolean j;
    public final /* synthetic */ C3008j0 k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C2983e0(C3008j0 c3008j0, Long l, String str, String str2, Bundle bundle, boolean z, boolean z2) {
        super(c3008j0, true);
        this.e = l;
        this.f = str;
        this.g = str2;
        this.h = bundle;
        this.i = z;
        this.j = z2;
        this.k = c3008j0;
    }

    @Override // com.google.android.gms.internal.measurement.AbstractRunnableC2988f0
    public final void a() {
        Long l = this.e;
        long jLongValue = l == null ? this.a : l.longValue();
        J j = this.k.i;
        com.google.android.gms.common.internal.u.h(j);
        j.logEvent(this.f, this.g, this.h, this.i, this.j, jLongValue);
    }
}

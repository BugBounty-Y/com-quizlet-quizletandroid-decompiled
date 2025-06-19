package com.google.android.gms.internal.measurement;

import android.os.Bundle;

/* loaded from: classes2.dex */
public final class U extends AbstractRunnableC2988f0 {
    public final /* synthetic */ int e;
    public final /* synthetic */ String f;
    public final /* synthetic */ String g;
    public final /* synthetic */ C3008j0 h;
    public final /* synthetic */ Object i;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ U(C3008j0 c3008j0, String str, String str2, Object obj, int i) {
        super(c3008j0, true);
        this.e = i;
        this.f = str;
        this.g = str2;
        this.i = obj;
        this.h = c3008j0;
    }

    @Override // com.google.android.gms.internal.measurement.AbstractRunnableC2988f0
    public final void a() {
        switch (this.e) {
            case 0:
                J j = this.h.i;
                com.google.android.gms.common.internal.u.h(j);
                j.setUserProperty(this.f, this.g, new com.google.android.gms.dynamic.b(this.i), true, this.a);
                break;
            case 1:
                J j2 = this.h.i;
                com.google.android.gms.common.internal.u.h(j2);
                j2.clearConditionalUserProperty(this.f, this.g, (Bundle) this.i);
                break;
            case 2:
                J j3 = this.h.i;
                com.google.android.gms.common.internal.u.h(j3);
                j3.getConditionalUserProperties(this.f, this.g, (G) this.i);
                break;
            default:
                J j4 = this.h.i;
                com.google.android.gms.common.internal.u.h(j4);
                j4.setCurrentScreenByScionActivityInfo((zzdj) this.i, this.f, this.g, this.a);
                break;
        }
    }

    @Override // com.google.android.gms.internal.measurement.AbstractRunnableC2988f0
    public void b() {
        switch (this.e) {
            case 2:
                ((G) this.i).t1(null);
                break;
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public U(C3008j0 c3008j0, zzdj zzdjVar, String str, String str2) {
        super(c3008j0, true);
        this.e = 3;
        this.i = zzdjVar;
        this.f = str;
        this.g = str2;
        this.h = c3008j0;
    }
}

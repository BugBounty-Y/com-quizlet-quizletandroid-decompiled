package com.google.android.gms.internal.measurement;

/* renamed from: com.google.android.gms.internal.measurement.b0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2968b0 extends AbstractRunnableC2988f0 {
    public final /* synthetic */ String e;
    public final /* synthetic */ String f;
    public final /* synthetic */ boolean g;
    public final /* synthetic */ G h;
    public final /* synthetic */ C3008j0 i;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C2968b0(C3008j0 c3008j0, String str, String str2, boolean z, G g) {
        super(c3008j0, true);
        this.e = str;
        this.f = str2;
        this.g = z;
        this.h = g;
        this.i = c3008j0;
    }

    @Override // com.google.android.gms.internal.measurement.AbstractRunnableC2988f0
    public final void a() {
        J j = this.i.i;
        com.google.android.gms.common.internal.u.h(j);
        j.getUserProperties(this.e, this.f, this.g, this.h);
    }

    @Override // com.google.android.gms.internal.measurement.AbstractRunnableC2988f0
    public final void b() {
        this.h.t1(null);
    }
}

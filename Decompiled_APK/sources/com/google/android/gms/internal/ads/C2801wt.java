package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.wt, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2801wt extends AbstractC2672tt {
    public final Object a;

    public C2801wt(Object obj) {
        this.a = obj;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2672tt
    public final AbstractC2672tt a(InterfaceC2544qt interfaceC2544qt) {
        Object objApply = interfaceC2544qt.apply(this.a);
        AbstractC1981ds.x(objApply, "the Function passed to Optional.transform() must not return null.");
        return new C2801wt(objApply);
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2672tt
    public final Object b() {
        return this.a;
    }

    public final boolean equals(Object obj) {
        if (obj instanceof C2801wt) {
            return this.a.equals(((C2801wt) obj).a);
        }
        return false;
    }

    public final int hashCode() {
        return this.a.hashCode() + 1502476572;
    }

    public final String toString() {
        return android.support.v4.media.session.a.B("Optional.of(", this.a.toString(), ")");
    }
}

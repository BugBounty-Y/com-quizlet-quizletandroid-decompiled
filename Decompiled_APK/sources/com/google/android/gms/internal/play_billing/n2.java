package com.google.android.gms.internal.play_billing;

/* loaded from: classes2.dex */
public final class n2 extends l2 {
    public final /* synthetic */ o2 h;

    public n2(o2 o2Var) {
        this.h = o2Var;
    }

    @Override // com.google.android.gms.internal.play_billing.l2
    public final String c() {
        m2 m2Var = (m2) this.h.a.get();
        return m2Var == null ? "Completer object has been garbage collected, future will fail soon" : android.support.v4.media.session.a.B("tag=[", String.valueOf(m2Var.a), "]");
    }
}

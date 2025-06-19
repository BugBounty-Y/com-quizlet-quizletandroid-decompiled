package com.google.android.gms.internal.play_billing;

/* renamed from: com.google.android.gms.internal.play_billing.q, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3827q extends AbstractC3835t {
    @Override // com.google.android.gms.internal.play_billing.AbstractC3835t
    public final int a() {
        return 0;
    }

    @Override // com.google.android.gms.internal.play_billing.AbstractC3835t
    public final AbstractC3835t b(AbstractC3841v abstractC3841v, AbstractC3841v abstractC3841v2) {
        int iCompareTo = abstractC3841v.compareTo(abstractC3841v2);
        return iCompareTo < 0 ? AbstractC3835t.b : iCompareTo > 0 ? AbstractC3835t.c : AbstractC3835t.a;
    }
}

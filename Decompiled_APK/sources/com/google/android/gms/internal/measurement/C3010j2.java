package com.google.android.gms.internal.measurement;

import com.google.android.gms.internal.ads.C1721Kc;
import java.util.List;

/* renamed from: com.google.android.gms.internal.measurement.j2, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3010j2 extends AbstractC2997h {
    public final /* synthetic */ int c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C3010j2(String str, int i) {
        super(str);
        this.c = i;
    }

    @Override // com.google.android.gms.internal.measurement.AbstractC2997h
    public final InterfaceC3027n d(C1721Kc c1721Kc, List list) {
        switch (this.c) {
            case 0:
                return InterfaceC3027n.Q0;
            case 1:
            case 2:
                return this;
            case 3:
                return new C2992g(Double.valueOf(0.0d));
            default:
                return InterfaceC3027n.Q0;
        }
    }
}

package com.google.android.gms.internal.measurement;

import com.google.android.gms.internal.ads.C1721Kc;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3554w3;
import java.util.Arrays;
import java.util.Comparator;

/* renamed from: com.google.android.gms.internal.measurement.u, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3061u implements Comparator {
    public final /* synthetic */ AbstractC2997h a;
    public final /* synthetic */ C1721Kc b;

    public C3061u(AbstractC2997h abstractC2997h, C1721Kc c1721Kc) {
        this.a = abstractC2997h;
        this.b = c1721Kc;
    }

    @Override // java.util.Comparator
    public final /* bridge */ /* synthetic */ int compare(Object obj, Object obj2) {
        InterfaceC3027n interfaceC3027n = (InterfaceC3027n) obj;
        InterfaceC3027n interfaceC3027n2 = (InterfaceC3027n) obj2;
        if (interfaceC3027n instanceof r) {
            return !(interfaceC3027n2 instanceof r) ? 1 : 0;
        }
        if (interfaceC3027n2 instanceof r) {
            return -1;
        }
        AbstractC2997h abstractC2997h = this.a;
        return abstractC2997h == null ? interfaceC3027n.zzi().compareTo(interfaceC3027n2.zzi()) : (int) AbstractC3554w3.a(abstractC2997h.d(this.b, Arrays.asList(interfaceC3027n, interfaceC3027n2)).g().doubleValue());
    }
}

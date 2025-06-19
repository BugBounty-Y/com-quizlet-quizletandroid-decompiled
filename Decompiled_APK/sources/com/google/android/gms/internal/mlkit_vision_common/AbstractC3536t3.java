package com.google.android.gms.internal.mlkit_vision_common;

import androidx.camera.camera2.internal.AbstractC0147y;
import com.google.android.gms.internal.ads.C1721Kc;
import com.google.android.gms.internal.measurement.AbstractC2997h;
import com.google.android.gms.internal.measurement.C3042q;
import com.google.android.gms.internal.measurement.C3056t;
import com.google.android.gms.internal.measurement.InterfaceC3007j;
import com.google.android.gms.internal.measurement.InterfaceC3027n;
import java.util.ArrayList;

/* renamed from: com.google.android.gms.internal.mlkit_vision_common.t3, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3536t3 {
    public static final /* synthetic */ int a = 0;

    public static InterfaceC3027n a(InterfaceC3007j interfaceC3007j, C3042q c3042q, C1721Kc c1721Kc, ArrayList arrayList) {
        String str = c3042q.a;
        if (interfaceC3007j.M(str)) {
            InterfaceC3027n interfaceC3027nA = interfaceC3007j.a(str);
            if (interfaceC3027nA instanceof AbstractC2997h) {
                return ((AbstractC2997h) interfaceC3027nA).d(c1721Kc, arrayList);
            }
            throw new IllegalArgumentException(android.support.v4.media.session.a.k(str, " is not a function"));
        }
        if (!"hasOwnProperty".equals(str)) {
            throw new IllegalArgumentException(AbstractC0147y.d("Object has no function ", str));
        }
        AbstractC3554w3.g("hasOwnProperty", arrayList, 1);
        return interfaceC3007j.M(((C3056t) c1721Kc.c).a(c1721Kc, (InterfaceC3027n) arrayList.get(0)).zzi()) ? InterfaceC3027n.V0 : InterfaceC3027n.W0;
    }
}

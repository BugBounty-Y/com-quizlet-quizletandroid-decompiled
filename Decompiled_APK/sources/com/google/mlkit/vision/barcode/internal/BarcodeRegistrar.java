package com.google.mlkit.vision.barcode.internal;

import com.google.android.gms.internal.ads.C2537qm;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3292x;
import com.google.firebase.components.ComponentRegistrar;
import com.google.firebase.components.j;
import com.onetrust.otpublishers.headless.Internal.Helper.h;
import java.util.List;

/* loaded from: classes2.dex */
public class BarcodeRegistrar implements ComponentRegistrar {
    @Override // com.google.firebase.components.ComponentRegistrar
    public final List getComponents() {
        C2537qm c2537qmB = com.google.firebase.components.a.b(d.class);
        c2537qmB.a(j.c(com.google.mlkit.common.sdkinternal.f.class));
        c2537qmB.f = new com.google.mlkit.common.sdkinternal.model.a(20);
        com.google.firebase.components.a aVarB = c2537qmB.b();
        C2537qm c2537qmB2 = com.google.firebase.components.a.b(b.class);
        c2537qmB2.a(j.c(d.class));
        c2537qmB2.a(j.c(com.google.mlkit.common.sdkinternal.d.class));
        c2537qmB2.a(j.c(com.google.mlkit.common.sdkinternal.f.class));
        c2537qmB2.f = new h(20);
        return AbstractC3292x.h(aVarB, c2537qmB2.b());
    }
}

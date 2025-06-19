package com.google.mlkit.vision.common.internal;

import com.google.android.gms.internal.ads.C2537qm;
import com.google.android.gms.internal.mlkit_vision_common.P4;
import com.google.android.gms.internal.mlkit_vision_common.R4;
import com.google.android.gms.internal.mlkit_vision_common.T4;
import com.google.firebase.components.ComponentRegistrar;
import com.google.firebase.components.j;
import java.util.List;

/* loaded from: classes2.dex */
public class VisionCommonRegistrar implements ComponentRegistrar {
    @Override // com.google.firebase.components.ComponentRegistrar
    public final List getComponents() {
        C2537qm c2537qmB = com.google.firebase.components.a.b(d.class);
        c2537qmB.a(new j(2, 0, c.class));
        c2537qmB.f = d.b;
        Object[] objArr = {c2537qmB.b()};
        for (int i = 0; i < 1; i++) {
            P4 p4 = R4.b;
            if (objArr[i] == null) {
                throw new NullPointerException(android.support.v4.media.session.a.f(i, "at index "));
            }
        }
        P4 p42 = R4.b;
        return new T4(objArr, 1);
    }
}

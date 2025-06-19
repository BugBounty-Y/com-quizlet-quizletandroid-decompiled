package com.google.mlkit.common.internal;

import com.google.android.gms.internal.ads.C2537qm;
import com.google.android.gms.internal.mlkit_common.u;
import com.google.android.gms.internal.mlkit_vision_common.D3;
import com.google.android.material.shape.e;
import com.google.firebase.components.ComponentRegistrar;
import com.google.firebase.components.a;
import com.google.firebase.components.j;
import com.google.mlkit.common.model.b;
import com.google.mlkit.common.model.c;
import com.google.mlkit.common.sdkinternal.f;
import com.google.mlkit.common.sdkinternal.g;
import com.google.mlkit.common.sdkinternal.i;
import com.quizlet.shared.usecase.folderstudymaterials.d;
import java.util.List;

/* loaded from: classes2.dex */
public class CommonComponentRegistrar implements ComponentRegistrar {
    @Override // com.google.firebase.components.ComponentRegistrar
    public final List getComponents() {
        a aVar = i.b;
        C2537qm c2537qmB = a.b(com.google.mlkit.common.sdkinternal.model.a.class);
        c2537qmB.a(j.c(f.class));
        c2537qmB.f = new d(19);
        a aVarB = c2537qmB.b();
        C2537qm c2537qmB2 = a.b(g.class);
        c2537qmB2.f = new com.quizlet.shared.usecase.srs.a(19);
        a aVarB2 = c2537qmB2.b();
        C2537qm c2537qmB3 = a.b(c.class);
        c2537qmB3.a(new j(2, 0, b.class));
        c2537qmB3.f = new com.quizlet.shared.usecase.studiableMetadata.a(19);
        a aVarB3 = c2537qmB3.b();
        C2537qm c2537qmB4 = a.b(com.google.mlkit.common.sdkinternal.d.class);
        c2537qmB4.a(new j(1, 1, g.class));
        c2537qmB4.f = new retrofit2.adapter.rxjava3.d(19);
        a aVarB4 = c2537qmB4.b();
        C2537qm c2537qmB5 = a.b(com.google.mlkit.common.sdkinternal.a.class);
        c2537qmB5.f = new assistantMode.utils.studiableMetadata.b(20);
        a aVarB5 = c2537qmB5.b();
        C2537qm c2537qmB6 = a.b(com.google.mlkit.common.sdkinternal.b.class);
        c2537qmB6.a(j.c(com.google.mlkit.common.sdkinternal.a.class));
        c2537qmB6.f = new u(20);
        a aVarB6 = c2537qmB6.b();
        C2537qm c2537qmB7 = a.b(com.google.mlkit.common.internal.model.a.class);
        c2537qmB7.a(j.c(f.class));
        c2537qmB7.f = new e(20);
        a aVarB7 = c2537qmB7.b();
        C2537qm c2537qmB8 = a.b(b.class);
        c2537qmB8.c = 1;
        c2537qmB8.a(new j(1, 1, com.google.mlkit.common.internal.model.a.class));
        c2537qmB8.f = new com.google.firebase.heartbeatinfo.e(20);
        a aVarB8 = c2537qmB8.b();
        com.google.android.gms.internal.mlkit_common.b bVar = com.google.android.gms.internal.mlkit_common.d.b;
        Object[] objArr = {aVar, aVarB, aVarB2, aVarB3, aVarB4, aVarB5, aVarB6, aVarB7, aVarB8};
        D3.a(9, objArr);
        return new com.google.android.gms.internal.mlkit_common.g(objArr, 9);
    }
}

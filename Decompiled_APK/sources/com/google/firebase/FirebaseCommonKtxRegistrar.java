package com.google.firebase;

import androidx.annotation.Keep;
import com.google.android.gms.internal.ads.C2537qm;
import com.google.firebase.components.ComponentRegistrar;
import com.google.firebase.components.j;
import com.google.firebase.components.q;
import java.util.List;
import java.util.concurrent.Executor;
import kotlin.Metadata;
import kotlin.collections.B;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.AbstractC5040y;
import org.jetbrains.annotations.NotNull;

@Keep
@Metadata
/* loaded from: classes2.dex */
public final class FirebaseCommonKtxRegistrar implements ComponentRegistrar {
    @Override // com.google.firebase.components.ComponentRegistrar
    @NotNull
    public List<com.google.firebase.components.a> getComponents() {
        C2537qm c2537qmA = com.google.firebase.components.a.a(new q(com.google.firebase.annotations.concurrent.a.class, AbstractC5040y.class));
        c2537qmA.a(new j(new q(com.google.firebase.annotations.concurrent.a.class, Executor.class), 1, 0));
        c2537qmA.f = c.c;
        com.google.firebase.components.a aVarB = c2537qmA.b();
        Intrinsics.checkNotNullExpressionValue(aVarB, "builder(Qualified.qualif…cher()\n    }\n    .build()");
        C2537qm c2537qmA2 = com.google.firebase.components.a.a(new q(com.google.firebase.annotations.concurrent.c.class, AbstractC5040y.class));
        c2537qmA2.a(new j(new q(com.google.firebase.annotations.concurrent.c.class, Executor.class), 1, 0));
        c2537qmA2.f = c.d;
        com.google.firebase.components.a aVarB2 = c2537qmA2.b();
        Intrinsics.checkNotNullExpressionValue(aVarB2, "builder(Qualified.qualif…cher()\n    }\n    .build()");
        C2537qm c2537qmA3 = com.google.firebase.components.a.a(new q(com.google.firebase.annotations.concurrent.b.class, AbstractC5040y.class));
        c2537qmA3.a(new j(new q(com.google.firebase.annotations.concurrent.b.class, Executor.class), 1, 0));
        c2537qmA3.f = c.e;
        com.google.firebase.components.a aVarB3 = c2537qmA3.b();
        Intrinsics.checkNotNullExpressionValue(aVarB3, "builder(Qualified.qualif…cher()\n    }\n    .build()");
        C2537qm c2537qmA4 = com.google.firebase.components.a.a(new q(com.google.firebase.annotations.concurrent.d.class, AbstractC5040y.class));
        c2537qmA4.a(new j(new q(com.google.firebase.annotations.concurrent.d.class, Executor.class), 1, 0));
        c2537qmA4.f = c.f;
        com.google.firebase.components.a aVarB4 = c2537qmA4.b();
        Intrinsics.checkNotNullExpressionValue(aVarB4, "builder(Qualified.qualif…cher()\n    }\n    .build()");
        return B.j(aVarB, aVarB2, aVarB3, aVarB4);
    }
}

package com.google.firebase.abt.component;

import android.content.Context;
import androidx.annotation.Keep;
import com.facebook.appevents.k;
import com.google.android.gms.internal.ads.C2537qm;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3700q;
import com.google.firebase.components.ComponentRegistrar;
import com.google.firebase.components.b;
import com.google.firebase.components.j;
import java.util.Arrays;
import java.util.List;

@Keep
/* loaded from: classes2.dex */
public class AbtRegistrar implements ComponentRegistrar {
    private static final String LIBRARY_NAME = "fire-abt";

    /* JADX INFO: Access modifiers changed from: private */
    public static /* synthetic */ a lambda$getComponents$0(b bVar) {
        return new a((Context) bVar.get(Context.class), bVar.b(com.google.firebase.analytics.connector.b.class));
    }

    @Override // com.google.firebase.components.ComponentRegistrar
    public List<com.google.firebase.components.a> getComponents() {
        C2537qm c2537qmB = com.google.firebase.components.a.b(a.class);
        c2537qmB.a = LIBRARY_NAME;
        c2537qmB.a(j.c(Context.class));
        c2537qmB.a(j.a(com.google.firebase.analytics.connector.b.class));
        c2537qmB.f = new k(28);
        return Arrays.asList(c2537qmB.b(), AbstractC3700q.a(LIBRARY_NAME, "21.1.1"));
    }
}

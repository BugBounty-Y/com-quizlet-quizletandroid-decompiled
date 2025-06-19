package com.google.android.gms.internal.mlkit_vision_document_scanner;

import android.content.Context;
import androidx.camera.camera2.internal.C0143u;
import com.google.android.gms.internal.ads.C2537qm;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.q, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3700q {
    public static final /* synthetic */ int a = 0;

    public static com.google.firebase.components.a a(String str, String str2) {
        com.google.firebase.platforminfo.a aVar = new com.google.firebase.platforminfo.a(str, str2);
        C2537qm c2537qmB = com.google.firebase.components.a.b(com.google.firebase.platforminfo.a.class);
        c2537qmB.c = 1;
        c2537qmB.f = new com.google.android.material.search.a(aVar, 2);
        return c2537qmB.b();
    }

    public static com.google.firebase.components.a b(String str, com.facebook.appevents.k kVar) {
        C2537qm c2537qmB = com.google.firebase.components.a.b(com.google.firebase.platforminfo.a.class);
        c2537qmB.c = 1;
        c2537qmB.a(com.google.firebase.components.j.c(Context.class));
        c2537qmB.f = new C0143u(25, str, kVar);
        return c2537qmB.b();
    }
}

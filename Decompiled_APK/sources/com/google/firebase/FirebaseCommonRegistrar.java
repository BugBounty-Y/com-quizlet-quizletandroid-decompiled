package com.google.firebase;

import android.content.Context;
import android.os.Build;
import com.facebook.appevents.k;
import com.google.android.gms.internal.ads.C2537qm;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3700q;
import com.google.firebase.components.ComponentRegistrar;
import com.google.firebase.components.j;
import com.google.firebase.components.n;
import com.google.firebase.components.q;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executor;
import kotlin.C4941j;

/* loaded from: classes2.dex */
public class FirebaseCommonRegistrar implements ComponentRegistrar {
    public static String a(String str) {
        return str.replace(' ', '_').replace('/', '_');
    }

    @Override // com.google.firebase.components.ComponentRegistrar
    public final List getComponents() {
        String str;
        ArrayList arrayList = new ArrayList();
        C2537qm c2537qmB = com.google.firebase.components.a.b(com.google.firebase.platforminfo.b.class);
        c2537qmB.a(new j(2, 0, com.google.firebase.platforminfo.a.class));
        c2537qmB.f = new n(23);
        arrayList.add(c2537qmB.b());
        q qVar = new q(com.google.firebase.annotations.concurrent.a.class, Executor.class);
        C2537qm c2537qm = new C2537qm(com.google.firebase.heartbeatinfo.d.class, new Class[]{com.google.firebase.heartbeatinfo.f.class, com.google.firebase.heartbeatinfo.g.class});
        c2537qm.a(j.c(Context.class));
        c2537qm.a(j.c(h.class));
        c2537qm.a(new j(2, 0, com.google.firebase.heartbeatinfo.e.class));
        c2537qm.a(new j(1, 1, com.google.firebase.platforminfo.b.class));
        c2537qm.a(new j(qVar, 1, 0));
        c2537qm.f = new com.google.firebase.heartbeatinfo.b(qVar, 0);
        arrayList.add(c2537qm.b());
        arrayList.add(AbstractC3700q.a("fire-android", String.valueOf(Build.VERSION.SDK_INT)));
        arrayList.add(AbstractC3700q.a("fire-core", "21.0.0"));
        arrayList.add(AbstractC3700q.a("device-name", a(Build.PRODUCT)));
        arrayList.add(AbstractC3700q.a("device-model", a(Build.DEVICE)));
        arrayList.add(AbstractC3700q.a("device-brand", a(Build.BRAND)));
        arrayList.add(AbstractC3700q.b("android-target-sdk", new k(24)));
        arrayList.add(AbstractC3700q.b("android-min-sdk", new k(25)));
        arrayList.add(AbstractC3700q.b("android-platform", new k(26)));
        arrayList.add(AbstractC3700q.b("android-installer", new k(27)));
        try {
            C4941j.c.getClass();
            str = "2.0.21";
        } catch (NoClassDefFoundError unused) {
            str = null;
        }
        if (str != null) {
            arrayList.add(AbstractC3700q.a("kotlin", str));
        }
        return arrayList;
    }
}

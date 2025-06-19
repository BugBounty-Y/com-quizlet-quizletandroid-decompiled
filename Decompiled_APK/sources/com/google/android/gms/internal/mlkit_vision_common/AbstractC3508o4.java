package com.google.android.gms.internal.mlkit_vision_common;

import com.google.common.base.Predicate;
import com.google.common.collect.C3920c;
import java.util.Arrays;
import java.util.Collection;

/* renamed from: com.google.android.gms.internal.mlkit_vision_common.o4, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3508o4 {
    public static C3920c a(Collection collection, Predicate predicate) {
        if (!(collection instanceof C3920c)) {
            collection.getClass();
            return new C3920c(collection, predicate);
        }
        C3920c c3920c = (C3920c) collection;
        Predicate predicate2 = c3920c.b;
        predicate2.getClass();
        return new C3920c(c3920c.a, new com.google.common.base.j(Arrays.asList(predicate2, predicate)));
    }

    /* JADX WARN: Removed duplicated region for block: B:12:0x003c  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static android.content.Intent[] b(com.quizlet.infra.androidcontracts.deeplink.a r8, android.content.Context r9, com.quizlet.quizletandroid.managers.deeplinks.h r10) {
        /*
            java.lang.String r0 = "context"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r9, r0)
            java.lang.String r0 = "checker"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r10, r0)
            android.content.Intent[] r8 = r8.a(r9)
            java.util.ArrayList r0 = new java.util.ArrayList
            r0.<init>()
            int r1 = r8.length
            r2 = 0
            r3 = r2
        L16:
            if (r3 >= r1) goto L45
            r4 = r8[r3]
            android.content.pm.PackageManager r5 = r9.getPackageManager()
            android.content.ComponentName r5 = r4.resolveActivity(r5)
            if (r5 == 0) goto L3c
            android.net.Uri r5 = r4.getData()
            r6 = 1
            if (r5 == 0) goto L38
            r10.getClass()
            java.lang.String r7 = "uri"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r5, r7)
            boolean r5 = com.quizlet.quizletandroid.ui.webpages.a.d(r5)
            goto L39
        L38:
            r5 = r6
        L39:
            if (r5 == 0) goto L3c
            goto L3d
        L3c:
            r6 = r2
        L3d:
            if (r6 == 0) goto L42
            r0.add(r4)
        L42:
            int r3 = r3 + 1
            goto L16
        L45:
            android.content.Intent[] r8 = new android.content.Intent[r2]
            java.lang.Object[] r8 = r0.toArray(r8)
            android.content.Intent[] r8 = (android.content.Intent[]) r8
            return r8
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_common.AbstractC3508o4.b(com.quizlet.infra.androidcontracts.deeplink.a, android.content.Context, com.quizlet.quizletandroid.managers.deeplinks.h):android.content.Intent[]");
    }
}

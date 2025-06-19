package com.google.firebase.messaging;

import android.os.Bundle;
import com.google.android.gms.internal.mlkit_vision_common.S3;
import com.google.android.gms.tasks.Task;
import java.io.IOException;
import java.util.concurrent.ExecutionException;

/* loaded from: classes2.dex */
public final class m {
    public final com.google.firebase.h a;
    public final o b;
    public final com.google.android.gms.cloudmessaging.a c;
    public final com.google.firebase.inject.b d;
    public final com.google.firebase.inject.b e;
    public final com.google.firebase.installations.d f;

    public m(com.google.firebase.h hVar, o oVar, com.google.firebase.inject.b bVar, com.google.firebase.inject.b bVar2, com.google.firebase.installations.d dVar) {
        hVar.a();
        com.google.android.gms.cloudmessaging.a aVar = new com.google.android.gms.cloudmessaging.a(hVar.a);
        this.a = hVar;
        this.b = oVar;
        this.c = aVar;
        this.d = bVar;
        this.e = bVar2;
        this.f = dVar;
    }

    public final Task a(Task task) {
        return task.e(new androidx.arch.core.executor.a(1), new com.google.android.material.search.a(this, 10));
    }

    /* JADX WARN: Removed duplicated region for block: B:39:0x00ea A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:66:0x0147 A[ADDED_TO_REGION, ORIG_RETURN, RETURN] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void b(java.lang.String r6, java.lang.String r7, android.os.Bundle r8) {
        /*
            Method dump skipped, instructions count: 332
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.firebase.messaging.m.b(java.lang.String, java.lang.String, android.os.Bundle):void");
    }

    public final Task c(String str, String str2, Bundle bundle) {
        int i;
        try {
            b(str, str2, bundle);
            com.google.android.gms.cloudmessaging.a aVar = this.c;
            com.google.android.gms.cloudmessaging.l lVar = aVar.c;
            int iA = lVar.a();
            com.google.android.gms.cloudmessaging.f fVar = com.google.android.gms.cloudmessaging.f.c;
            if (iA < 12000000) {
                return lVar.b() != 0 ? aVar.a(bundle).f(fVar, new com.quizlet.data.interactor.school.b(9, aVar, bundle)) : S3.h(new IOException("MISSING_INSTANCEID_SERVICE"));
            }
            com.google.android.gms.cloudmessaging.k kVarP = com.google.android.gms.cloudmessaging.k.p(aVar.b);
            synchronized (kVarP) {
                i = kVarP.b;
                kVarP.b = i + 1;
            }
            return kVarP.q(new com.google.android.gms.cloudmessaging.j(i, 1, bundle, 1)).e(fVar, com.google.android.gms.cloudmessaging.c.b);
        } catch (InterruptedException | ExecutionException e) {
            return S3.h(e);
        }
    }
}

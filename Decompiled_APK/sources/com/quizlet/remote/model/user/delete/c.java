package com.quizlet.remote.model.user.delete;

import android.os.RemoteException;
import com.android.installreferrer.api.InstallReferrerClient;
import com.android.installreferrer.api.InstallReferrerStateListener;
import com.android.installreferrer.api.ReferrerDetails;
import com.quizlet.remote.service.E;
import com.snowplowanalytics.core.tracker.d;
import com.snowplowanalytics.core.tracker.e;
import io.reactivex.rxjava3.core.q;
import io.reactivex.rxjava3.internal.operators.single.f;
import java.io.UnsupportedEncodingException;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.AbstractC5040y;

/* loaded from: classes3.dex */
public final class c implements InstallReferrerStateListener, q {
    public final Object a;
    public final Object b;

    public /* synthetic */ c(Object obj, Object obj2) {
        this.a = obj;
        this.b = obj2;
    }

    @Override // io.reactivex.rxjava3.core.q
    public void a(io.reactivex.rxjava3.disposables.b bVar) {
        io.reactivex.rxjava3.internal.disposables.a.c((f) this.a, bVar);
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object b(kotlin.coroutines.jvm.internal.c r5) {
        /*
            r4 = this;
            boolean r0 = r5 instanceof com.quizlet.remote.model.user.delete.a
            if (r0 == 0) goto L13
            r0 = r5
            com.quizlet.remote.model.user.delete.a r0 = (com.quizlet.remote.model.user.delete.a) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.remote.model.user.delete.a r0 = new com.quizlet.remote.model.user.delete.a
            r0.<init>(r4, r5)
        L18:
            java.lang.Object r5 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L2f
            if (r2 != r3) goto L27
            androidx.glance.appwidget.protobuf.Z.e(r5)
            goto L45
        L27:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r0)
            throw r5
        L2f:
            androidx.glance.appwidget.protobuf.Z.e(r5)
            com.quizlet.remote.model.user.delete.b r5 = new com.quizlet.remote.model.user.delete.b
            r2 = 0
            r5.<init>(r4, r2)
            r0.l = r3
            java.lang.Object r2 = r4.b
            kotlinx.coroutines.y r2 = (kotlinx.coroutines.AbstractC5040y) r2
            java.lang.Object r5 = kotlinx.coroutines.E.J(r2, r5, r0)
            if (r5 != r1) goto L45
            return r1
        L45:
            kotlin.r r5 = (kotlin.r) r5
            java.lang.Object r5 = r5.a
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.remote.model.user.delete.c.b(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    @Override // io.reactivex.rxjava3.core.q
    public void onError(Throwable th) {
        ((q) this.b).onError(th);
    }

    @Override // com.android.installreferrer.api.InstallReferrerStateListener
    public void onInstallReferrerServiceDisconnected() {
    }

    @Override // com.android.installreferrer.api.InstallReferrerStateListener
    public void onInstallReferrerSetupFinished(int i) throws IllegalAccessException, IllegalArgumentException, UnsupportedEncodingException {
        androidx.compose.ui.viewinterop.b bVar = (androidx.compose.ui.viewinterop.b) this.b;
        if (i != 0) {
            if (i == 1) {
                Intrinsics.checkNotNullExpressionValue("d", "TAG");
                e.a("d", "Install referrer API connection couldn't be established.", new Object[0]);
                bVar.invoke(null);
                return;
            } else {
                if (i != 2) {
                    return;
                }
                Intrinsics.checkNotNullExpressionValue("d", "TAG");
                e.a("d", "Install referrer API not available on the current Play Store app.", new Object[0]);
                bVar.invoke(null);
                return;
            }
        }
        try {
            ReferrerDetails installReferrer = ((InstallReferrerClient) this.a).getInstallReferrer();
            Intrinsics.checkNotNullExpressionValue(installReferrer, "referrerClient.installReferrer");
            String installReferrer2 = installReferrer.getInstallReferrer();
            Intrinsics.checkNotNullExpressionValue(installReferrer2, "response.installReferrer");
            bVar.invoke(new d(installReferrer.getReferrerClickTimestampSeconds(), installReferrer.getInstallBeginTimestampSeconds(), installReferrer2, installReferrer.getGooglePlayInstantParam()));
        } catch (RemoteException unused) {
            Intrinsics.checkNotNullExpressionValue("d", "TAG");
            e.a("d", "Install referrer API remote exception.", new Object[0]);
            bVar.invoke(null);
        } catch (NoSuchMethodError unused2) {
            Intrinsics.checkNotNullExpressionValue("d", "TAG");
            e.a("d", "Upgrade InstallReferrer package to v1.1 or higher to add the install referrer details entity.", new Object[0]);
            bVar.invoke(null);
        }
    }

    @Override // io.reactivex.rxjava3.core.q, com.google.android.gms.tasks.d
    public void onSuccess(Object obj) {
        ((q) this.b).onSuccess(obj);
    }

    public c(E service, AbstractC5040y ioDispatcher) {
        Intrinsics.checkNotNullParameter(service, "service");
        Intrinsics.checkNotNullParameter(ioDispatcher, "ioDispatcher");
        this.a = service;
        this.b = ioDispatcher;
    }
}

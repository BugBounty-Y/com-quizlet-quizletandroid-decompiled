package com.quizlet.data.repository.classmembership;

import android.util.Base64;
import android.util.JsonWriter;
import androidx.collection.V;
import androidx.compose.foundation.text.input.internal.u;
import com.android.billingclient.api.s;
import com.google.android.gms.ads.internal.client.r;
import com.google.android.gms.ads.internal.util.client.e;
import com.google.android.gms.ads.internal.util.client.f;
import com.google.android.gms.internal.ads.AbstractC2330lu;
import com.google.android.gms.internal.ads.AbstractC2773w7;
import com.google.android.gms.internal.ads.Bu;
import com.google.android.gms.internal.ads.C2227jd;
import com.google.android.gms.internal.ads.C2244ju;
import com.google.android.gms.internal.ads.C2799wr;
import com.google.android.gms.internal.ads.Fi;
import com.google.android.gms.internal.ads.Qv;
import com.quizlet.db.data.caches.UserInfoCache;
import com.quizlet.quizletandroid.ui.live.interstitial.QuizletLiveInterstitialActivity;
import com.quizlet.quizletandroid.ui.live.interstitial.d;
import io.reactivex.rxjava3.internal.operators.completable.m;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Map;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class c implements e {
    public final Object a;
    public final Object b;
    public final Object c;
    public Object d;

    public /* synthetic */ c(Object obj, Object obj2, Object obj3, Object obj4) {
        this.a = obj;
        this.b = obj2;
        this.c = obj3;
        this.d = obj4;
    }

    public void a(Object obj, ArrayList arrayList, HashSet hashSet) {
        if (arrayList.contains(obj)) {
            return;
        }
        if (hashSet.contains(obj)) {
            throw new RuntimeException("This graph contains cyclic dependencies");
        }
        hashSet.add(obj);
        ArrayList arrayList2 = (ArrayList) ((V) this.b).get(obj);
        if (arrayList2 != null) {
            int size = arrayList2.size();
            for (int i = 0; i < size; i++) {
                a(arrayList2.get(i), arrayList, hashSet);
            }
        }
        hashSet.remove(obj);
        arrayList.add(obj);
    }

    public m b(long j) {
        m mVar = new m(new io.reactivex.rxjava3.internal.operators.flowable.b(new a(this, j, 0), 4), new b(this, j, 0), null, 2);
        Intrinsics.checkNotNullExpressionValue(mVar, "onErrorReturn(...)");
        return mVar;
    }

    public d c() {
        QuizletLiveInterstitialActivity quizletLiveInterstitialActivity = (QuizletLiveInterstitialActivity) this.d;
        if (quizletLiveInterstitialActivity != null) {
            return quizletLiveInterstitialActivity;
        }
        Intrinsics.m("view");
        throw null;
    }

    /* JADX WARN: Removed duplicated region for block: B:30:0x0084  */
    /* JADX WARN: Removed duplicated region for block: B:34:0x0090  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object d(kotlin.coroutines.jvm.internal.c r6) {
        /*
            r5 = this;
            boolean r0 = r6 instanceof com.quizlet.data.interactor.home.a
            if (r0 == 0) goto L13
            r0 = r6
            com.quizlet.data.interactor.home.a r0 = (com.quizlet.data.interactor.home.a) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.data.interactor.home.a r0 = new com.quizlet.data.interactor.home.a
            r0.<init>(r5, r6)
        L18:
            java.lang.Object r6 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L3a
            if (r2 == r4) goto L34
            if (r2 != r3) goto L2c
            com.quizlet.data.repository.classmembership.c r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L6d
        L2c:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r0)
            throw r6
        L34:
            com.quizlet.data.repository.classmembership.c r2 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L55
        L3a:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            r0.j = r5
            r0.m = r4
            java.lang.Object r6 = r5.c
            com.quizlet.featuregate.features.home.a r6 = (com.quizlet.featuregate.features.home.a) r6
            java.lang.Object r2 = r5.b
            androidx.work.impl.model.c r2 = (androidx.work.impl.model.c) r2
            io.reactivex.rxjava3.core.p r6 = r6.b(r2)
            java.lang.Object r6 = com.google.android.gms.internal.mlkit_vision_camera.I1.b(r6, r0)
            if (r6 != r1) goto L54
            goto L6b
        L54:
            r2 = r5
        L55:
            java.lang.Boolean r6 = (java.lang.Boolean) r6
            boolean r6 = r6.booleanValue()
            if (r6 == 0) goto L75
            java.lang.Object r6 = r2.d
            com.lyft.android.scissors.b r6 = (com.lyft.android.scissors.b) r6
            r0.j = r2
            r0.m = r3
            java.lang.Object r6 = r6.a(r0)
            if (r6 != r1) goto L6c
        L6b:
            return r1
        L6c:
            r0 = r2
        L6d:
            java.lang.Number r6 = (java.lang.Number) r6
            int r6 = r6.intValue()
            r2 = r0
            goto L76
        L75:
            r6 = 0
        L76:
            com.quizlet.data.model.v2 r0 = new com.quizlet.data.model.v2
            java.lang.Object r1 = r2.a
            com.quizlet.db.data.caches.UserInfoCache r1 = (com.quizlet.db.data.caches.UserInfoCache) r1
            java.lang.String r1 = r1.getUsername()
            java.lang.String r3 = ""
            if (r1 != 0) goto L85
            r1 = r3
        L85:
            java.lang.Object r2 = r2.a
            com.quizlet.db.data.caches.UserInfoCache r2 = (com.quizlet.db.data.caches.UserInfoCache) r2
            java.lang.String r2 = r2.getProfileImage()
            if (r2 != 0) goto L90
            goto L91
        L90:
            r3 = r2
        L91:
            r0.<init>(r6, r1, r3)
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.classmembership.c.d(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public void e(int i, com.google.common.util.concurrent.e eVar) {
        if (((Boolean) r.d.c.a(AbstractC2773w7.o2)).booleanValue()) {
            eVar.a(new Qv(0, eVar, new s(this, i, 15)), (C2227jd) this.a);
        }
    }

    @Override // com.google.android.gms.ads.internal.util.client.e
    public void i(JsonWriter jsonWriter) throws IOException {
        jsonWriter.name("params").beginObject();
        jsonWriter.name("firstline").beginObject();
        jsonWriter.name("uri").value((String) this.a);
        jsonWriter.name("verb").value((String) this.b);
        jsonWriter.endObject();
        f.e(jsonWriter, (Map) this.c);
        byte[] bArr = (byte[]) this.d;
        if (bArr != null) {
            jsonWriter.name("body").value(Base64.encodeToString(bArr, 0));
        }
        jsonWriter.endObject();
    }

    public c(Bu bu, Fi fi, C2799wr c2799wr, C2799wr c2799wr2) {
        Object objN;
        if (bu != null) {
            objN = AbstractC2330lu.n(bu);
        } else {
            C2244ju c2244ju = AbstractC2330lu.b;
            objN = Bu.e;
        }
        this.a = objN;
        this.b = fi;
        this.c = c2799wr;
        this.d = c2799wr2;
    }

    public c(UserInfoCache userInfo, androidx.work.impl.model.c userProperties, com.quizlet.featuregate.features.home.a activityCenterFeature, com.lyft.android.scissors.b getActivityCenterUnreadCountUseCase) {
        Intrinsics.checkNotNullParameter(userInfo, "userInfo");
        Intrinsics.checkNotNullParameter(userProperties, "userProperties");
        Intrinsics.checkNotNullParameter(activityCenterFeature, "activityCenterFeature");
        Intrinsics.checkNotNullParameter(getActivityCenterUnreadCountUseCase, "getActivityCenterUnreadCountUseCase");
        this.a = userInfo;
        this.b = userProperties;
        this.c = activityCenterFeature;
        this.d = getActivityCenterUnreadCountUseCase;
    }

    public c(u remote, com.quizlet.data.repository.activitycenter.b local, org.slf4j.b logger, com.quizlet.data.connectivity.a networkManager) {
        Intrinsics.checkNotNullParameter(remote, "remote");
        Intrinsics.checkNotNullParameter(local, "local");
        Intrinsics.checkNotNullParameter(logger, "logger");
        Intrinsics.checkNotNullParameter(networkManager, "networkManager");
        this.a = remote;
        this.b = local;
        this.c = logger;
        this.d = networkManager;
    }

    public c(com.quizlet.infra.legacysyncengine.managers.d loggedInUserManager, com.quizlet.features.emailconfirmation.logging.a eventLogger) {
        Intrinsics.checkNotNullParameter(loggedInUserManager, "loggedInUserManager");
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        this.a = loggedInUserManager;
        this.b = eventLogger;
        this.c = new io.reactivex.rxjava3.disposables.a();
    }

    public c(com.snowplowanalytics.snowplow.util.a basisForProcessing, String str, String str2, String str3) {
        Intrinsics.checkNotNullParameter(basisForProcessing, "basisForProcessing");
        this.a = basisForProcessing;
        this.b = str;
        this.c = str2;
        this.d = str3;
    }

    public c() {
        this.a = new androidx.constraintlayout.core.d(10);
        this.b = new V(0);
        this.c = new ArrayList();
        this.d = new HashSet();
    }
}

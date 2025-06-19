package com.quizlet.remote.model.set;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.quizletandroid.k;
import io.reactivex.rxjava3.core.h;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.concurrent.ConcurrentHashMap;
import kotlin.collections.C;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.p;
import kotlin.r;
import kotlin.reflect.o;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.internal.C5043a0;
import kotlinx.serialization.internal.InterfaceC5045b0;
import kotlinx.serialization.internal.L;

/* loaded from: classes3.dex */
public final class d implements h, InterfaceC5045b0 {
    public final Object a;
    public final Object b;

    public d(com.quizlet.quizletandroid.ui.login.h bannerRepository, com.quizlet.search.logging.a bannerEventLogger) {
        Intrinsics.checkNotNullParameter(bannerRepository, "bannerRepository");
        Intrinsics.checkNotNullParameter(bannerEventLogger, "bannerEventLogger");
        this.a = bannerRepository;
        this.b = bannerEventLogger;
    }

    @Override // io.reactivex.rxjava3.core.h
    public void a(io.reactivex.rxjava3.disposables.b bVar) {
        io.reactivex.rxjava3.internal.disposables.a.e((io.reactivex.rxjava3.internal.observers.e) this.b, bVar);
    }

    @Override // kotlinx.serialization.internal.InterfaceC5045b0
    public Object b(kotlin.reflect.c key, ArrayList types) {
        Object objB;
        Object objPutIfAbsent;
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(types, "types");
        ConcurrentHashMap concurrentHashMap = (ConcurrentHashMap) this.b;
        Class clsB = kotlin.jvm.a.b(key);
        Object c5043a0 = concurrentHashMap.get(clsB);
        if (c5043a0 == null && (objPutIfAbsent = concurrentHashMap.putIfAbsent(clsB, (c5043a0 = new C5043a0()))) != null) {
            c5043a0 = objPutIfAbsent;
        }
        C5043a0 c5043a02 = (C5043a0) c5043a0;
        ArrayList arrayList = new ArrayList(C.q(types, 10));
        Iterator it2 = types.iterator();
        while (it2.hasNext()) {
            arrayList.add(new L((o) it2.next()));
        }
        ConcurrentHashMap concurrentHashMap2 = c5043a02.a;
        Object obj = concurrentHashMap2.get(arrayList);
        if (obj == null) {
            try {
                p pVar = r.b;
                objB = (KSerializer) ((Function2) this.a).invoke(key, types);
            } catch (Throwable th) {
                p pVar2 = r.b;
                objB = Z.b(th);
            }
            r rVar = new r(objB);
            Object objPutIfAbsent2 = concurrentHashMap2.putIfAbsent(arrayList, rVar);
            obj = objPutIfAbsent2 == null ? rVar : objPutIfAbsent2;
        }
        Intrinsics.checkNotNullExpressionValue(obj, "getOrPut(...)");
        return ((r) obj).a;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object c(java.lang.String r5, kotlin.coroutines.jvm.internal.c r6) {
        /*
            r4 = this;
            boolean r0 = r6 instanceof com.quizlet.search.data.blended.k
            if (r0 == 0) goto L13
            r0 = r6
            com.quizlet.search.data.blended.k r0 = (com.quizlet.search.data.blended.k) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.search.data.blended.k r0 = new com.quizlet.search.data.blended.k
            r0.<init>(r4, r6)
        L18:
            java.lang.Object r6 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L31
            if (r2 != r3) goto L29
            com.quizlet.remote.model.set.d r5 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L44
        L29:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            r0.j = r4
            r0.m = r3
            java.lang.Object r6 = r4.a
            com.quizlet.quizletandroid.ui.login.h r6 = (com.quizlet.quizletandroid.ui.login.h) r6
            java.lang.Object r6 = r6.g(r5, r0)
            if (r6 != r1) goto L43
            return r1
        L43:
            r5 = r4
        L44:
            com.quizlet.data.model.search.c r6 = (com.quizlet.data.model.search.c) r6
            if (r6 == 0) goto L78
            r5.getClass()
            int[] r0 = com.quizlet.search.data.blended.j.a
            com.quizlet.generated.enums.W0 r1 = r6.c
            int r1 = r1.ordinal()
            r0 = r0[r1]
            if (r0 == r3) goto L64
            r1 = 2
            if (r0 == r1) goto L64
            r1 = 3
            if (r0 != r1) goto L5e
            goto L64
        L5e:
            kotlin.NoWhenBranchMatchedException r5 = new kotlin.NoWhenBranchMatchedException
            r5.<init>()
            throw r5
        L64:
            java.lang.Object r5 = r5.b
            com.quizlet.search.logging.a r5 = (com.quizlet.search.logging.a) r5
            java.lang.String r0 = "banner"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r6, r0)
            java.lang.String r0 = "search_banner_shown"
            r5.a(r6, r0)
            com.quizlet.ui.models.search.c r5 = new com.quizlet.ui.models.search.c
            r5.<init>(r6)
            return r5
        L78:
            r5 = 0
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.remote.model.set.d.c(java.lang.String, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object d(kotlin.coroutines.jvm.internal.c r9) {
        /*
            r8 = this;
            boolean r0 = r9 instanceof com.quizlet.remote.model.set.b
            if (r0 == 0) goto L13
            r0 = r9
            com.quizlet.remote.model.set.b r0 = (com.quizlet.remote.model.set.b) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.remote.model.set.b r0 = new com.quizlet.remote.model.set.b
            r0.<init>(r8, r9)
        L18:
            java.lang.Object r9 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L31
            if (r2 != r3) goto L29
            com.quizlet.remote.model.set.d r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto L46
        L29:
            java.lang.IllegalStateException r9 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r9.<init>(r0)
            throw r9
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            r0.j = r8
            r0.m = r3
            java.lang.Object r9 = r8.a
            com.quizlet.remote.model.set.a r9 = (com.quizlet.remote.model.set.a) r9
            com.quizlet.remote.service.u r9 = r9.b
            java.lang.Object r9 = r9.a(r0)
            if (r9 != r1) goto L45
            return r1
        L45:
            r0 = r8
        L46:
            com.quizlet.remote.model.base.ApiThreeWrapper r9 = (com.quizlet.remote.model.base.ApiThreeWrapper) r9
            java.util.List r9 = r9.a
            if (r9 == 0) goto Lb4
            java.lang.Object r0 = r0.b
            com.quizlet.remote.model.set.e r0 = (com.quizlet.remote.model.set.e) r0
            java.lang.String r1 = "responses"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r9, r1)
            java.util.ArrayList r1 = new java.util.ArrayList
            r2 = 10
            int r3 = kotlin.collections.C.q(r9, r2)
            r1.<init>(r3)
            java.util.Iterator r9 = r9.iterator()
        L64:
            boolean r3 = r9.hasNext()
            if (r3 == 0) goto Lab
            java.lang.Object r3 = r9.next()
            com.quizlet.remote.model.set.RecommendedSetsAgeLocationBasedResponse r3 = (com.quizlet.remote.model.set.RecommendedSetsAgeLocationBasedResponse) r3
            com.quizlet.remote.model.set.RecommendedSetsAgeLocationBasedResponse$RecommendedSetsAgeLocationBasedModels r3 = r3.d
            java.util.List r3 = r3.a
            com.quizlet.quizletandroid.ui.profile.data.b r4 = r0.b
            java.lang.String r5 = "remotes"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r3, r5)
            java.util.ArrayList r3 = com.google.android.gms.internal.mlkit_vision_barcode.S.f(r4, r3)
            java.util.ArrayList r4 = new java.util.ArrayList
            int r5 = kotlin.collections.C.q(r3, r2)
            r4.<init>(r5)
            java.util.Iterator r3 = r3.iterator()
        L8c:
            boolean r5 = r3.hasNext()
            if (r5 == 0) goto La2
            java.lang.Object r5 = r3.next()
            com.quizlet.data.model.StudySet r5 = (com.quizlet.data.model.StudySet) r5
            com.quizlet.data.model.StudySetWithCreator r6 = new com.quizlet.data.model.StudySetWithCreator
            r7 = 0
            r6.<init>(r5, r7)
            r4.add(r6)
            goto L8c
        La2:
            com.quizlet.data.model.p1 r3 = new com.quizlet.data.model.p1
            r3.<init>(r4)
            r1.add(r3)
            goto L64
        Lab:
            java.lang.Object r9 = kotlin.collections.CollectionsKt.firstOrNull(r1)
            com.quizlet.data.model.p1 r9 = (com.quizlet.data.model.C4157p1) r9
            if (r9 == 0) goto Lb4
            return r9
        Lb4:
            com.quizlet.data.model.p1 r9 = new com.quizlet.data.model.p1
            kotlin.collections.K r0 = kotlin.collections.K.a
            r9.<init>(r0)
            return r9
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.remote.model.set.d.d(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    @Override // io.reactivex.rxjava3.core.h
    public void onComplete() {
        ((h) this.a).onComplete();
    }

    @Override // io.reactivex.rxjava3.core.h
    public void onError(Throwable th) {
        ((h) this.a).onError(th);
    }

    @Override // io.reactivex.rxjava3.core.h, io.reactivex.rxjava3.core.q, com.google.android.gms.tasks.d
    public void onSuccess(Object obj) {
        ((h) this.a).onSuccess(obj);
    }

    public d(a dataSource, e recommendedSetMapper, com.quizlet.quizletandroid.ui.profile.b irrelevantRecommendationMapper) {
        Intrinsics.checkNotNullParameter(dataSource, "dataSource");
        Intrinsics.checkNotNullParameter(recommendedSetMapper, "recommendedSetMapper");
        Intrinsics.checkNotNullParameter(irrelevantRecommendationMapper, "irrelevantRecommendationMapper");
        this.a = dataSource;
        this.b = recommendedSetMapper;
    }

    public d(k serializer, com.quizlet.quizletandroid.ui.login.h deserializer) {
        Intrinsics.checkNotNullParameter(serializer, "serializer");
        Intrinsics.checkNotNullParameter(deserializer, "deserializer");
        this.a = serializer;
        this.b = deserializer;
    }

    public d(h hVar, io.reactivex.rxjava3.internal.observers.e eVar) {
        this.a = hVar;
        this.b = eVar;
    }

    public d(Function2 compute) {
        Intrinsics.checkNotNullParameter(compute, "compute");
        this.a = compute;
        this.b = new ConcurrentHashMap();
    }
}

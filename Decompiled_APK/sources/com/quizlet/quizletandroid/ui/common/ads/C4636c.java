package com.quizlet.quizletandroid.ui.common.ads;

import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.internal.mlkit_vision_barcode.S;
import com.j256.ormlite.stmt.query.SimpleComparison;
import com.quizlet.features.infra.models.Creator;
import com.quizlet.generated.enums.w1;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.startpage.nav2.model.C4717m;
import com.quizlet.remote.model.base.ApiThreeWrapper;
import com.quizlet.remote.model.practicetests.QuestionCompatibility;
import com.quizlet.remote.model.user.RemoteUser;
import com.quizlet.remote.model.user.UserModels;
import com.quizlet.remote.model.user.UserResponse;
import dagger.android.DispatchingAndroidInjector$InvalidInjectorBindingException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import kotlin.collections.CollectionsKt;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.quizletandroid.ui.common.ads.c, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4636c implements io.reactivex.rxjava3.functions.h, dagger.android.b, io.reactivex.rxjava3.core.q {
    public final /* synthetic */ int a;
    public final Object b;

    public /* synthetic */ C4636c(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // io.reactivex.rxjava3.core.q
    public void a(io.reactivex.rxjava3.disposables.b bVar) {
        ((io.reactivex.rxjava3.core.b) this.b).a(bVar);
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        UserModels userModels;
        List list;
        switch (this.a) {
            case 3:
                List folders = (List) obj;
                Intrinsics.checkNotNullParameter(folders, "folders");
                if (folders.isEmpty()) {
                    return K.a;
                }
                List<com.quizlet.features.infra.models.folders.a> listP0 = CollectionsKt.p0(folders, 6);
                ((androidx.work.impl.model.e) this.b).getClass();
                ArrayList arrayList = new ArrayList(kotlin.collections.C.q(listP0, 10));
                for (com.quizlet.features.infra.models.folders.a aVar : listP0) {
                    Intrinsics.checkNotNullParameter(aVar, "<this>");
                    long j = aVar.a;
                    Creator creator = aVar.d;
                    String str = creator != null ? creator.b : null;
                    if (str == null) {
                        str = "";
                    }
                    String str2 = creator != null ? creator.c : null;
                    arrayList.add(new C4717m(new com.quizlet.ui.models.content.carditem.c(creator != null ? creator.d : R.string.empty, j, aVar.b, str, str2 == null ? "" : str2, creator != null ? creator.e : false), Long.valueOf(aVar.a), w1.RECENT_FEED));
                }
                return kotlin.collections.A.b(new com.quizlet.quizletandroid.ui.startpage.nav2.model.y(arrayList));
            case 4:
                List it2 = (List) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                return ((com.quizlet.remote.mapper.base.a) this.b).e(it2);
            default:
                ApiThreeWrapper response = (ApiThreeWrapper) obj;
                Intrinsics.checkNotNullParameter(response, "response");
                UserResponse userResponse = (UserResponse) response.a();
                if (userResponse == null || (userModels = userResponse.d) == null || (list = userModels.a) == null) {
                    return K.a;
                }
                ArrayList remotes = new ArrayList(kotlin.collections.C.q(list, 10));
                int i = 0;
                for (Object obj2 : list) {
                    int i2 = i + 1;
                    if (i < 0) {
                        kotlin.collections.B.p();
                        throw null;
                    }
                    remotes.add((RemoteUser) obj2);
                    i = i2;
                }
                com.quizlet.quizletandroid.ui.activitycenter.models.a aVar2 = (com.quizlet.quizletandroid.ui.activitycenter.models.a) this.b;
                Intrinsics.checkNotNullParameter(remotes, "remotes");
                return S.f(aVar2, remotes);
        }
    }

    public String b() {
        String strF = ((com.squareup.moshi.l) this.b).f(new QuestionCompatibility(null, null, null, 7, null));
        Intrinsics.checkNotNullExpressionValue(strF, "toJson(...)");
        return strF;
    }

    /* JADX WARN: Removed duplicated region for block: B:8:0x0014  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object c(long r9, com.quizlet.remote.model.base.PagingInfo r11, kotlin.coroutines.jvm.internal.c r12) {
        /*
            r8 = this;
            boolean r0 = r12 instanceof com.quizlet.remote.model.term.a
            if (r0 == 0) goto L14
            r0 = r12
            com.quizlet.remote.model.term.a r0 = (com.quizlet.remote.model.term.a) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L14
            int r1 = r1 - r2
            r0.m = r1
        L12:
            r6 = r0
            goto L1a
        L14:
            com.quizlet.remote.model.term.a r0 = new com.quizlet.remote.model.term.a
            r0.<init>(r8, r12)
            goto L12
        L1a:
            java.lang.Object r12 = r6.k
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r6.m
            r2 = 1
            if (r1 == 0) goto L36
            if (r1 != r2) goto L2e
            com.quizlet.remote.model.base.a r9 = r6.j
            androidx.glance.appwidget.protobuf.Z.e(r12)     // Catch: java.lang.Exception -> L2b
            goto L5d
        L2b:
            r0 = move-exception
            r9 = r0
            goto L64
        L2e:
            java.lang.IllegalStateException r9 = new java.lang.IllegalStateException
            java.lang.String r10 = "call to 'resume' before 'invoke' with coroutine"
            r9.<init>(r10)
            throw r9
        L36:
            androidx.glance.appwidget.protobuf.Z.e(r12)
            com.quizlet.remote.model.base.a r12 = com.quizlet.remote.model.base.a.a
            java.lang.Object r1 = r8.b     // Catch: java.lang.Exception -> L2b
            com.quizlet.remote.service.C r1 = (com.quizlet.remote.service.C) r1     // Catch: java.lang.Exception -> L2b
            java.lang.Boolean r4 = java.lang.Boolean.FALSE     // Catch: java.lang.Exception -> L2b
            if (r11 == 0) goto L49
            java.util.LinkedHashMap r11 = r11.a()     // Catch: java.lang.Exception -> L2b
        L47:
            r5 = r11
            goto L4e
        L49:
            kotlin.collections.L r11 = kotlin.collections.V.c()     // Catch: java.lang.Exception -> L2b
            goto L47
        L4e:
            r6.j = r12     // Catch: java.lang.Exception -> L2b
            r6.m = r2     // Catch: java.lang.Exception -> L2b
            r2 = r9
            java.lang.Object r9 = r1.a(r2, r4, r5, r6)     // Catch: java.lang.Exception -> L2b
            if (r9 != r0) goto L5a
            return r0
        L5a:
            r7 = r12
            r12 = r9
            r9 = r7
        L5d:
            com.quizlet.remote.model.base.ApiThreeWrapper r12 = (com.quizlet.remote.model.base.ApiThreeWrapper) r12     // Catch: java.lang.Exception -> L2b
            java.lang.Object r9 = com.google.android.gms.internal.mlkit_vision_barcode.V.c(r12, r9)     // Catch: java.lang.Exception -> L2b
            return r9
        L64:
            kotlin.p r10 = kotlin.r.b
            kotlin.q r9 = androidx.glance.appwidget.protobuf.Z.b(r9)
            return r9
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.common.ads.C4636c.c(long, com.quizlet.remote.model.base.PagingInfo, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    @Override // dagger.android.b
    public void d(Object obj) {
        String name = obj.getClass().getName();
        Map map = (Map) this.b;
        javax.inject.a aVar = (javax.inject.a) map.get(name);
        if (aVar != null) {
            dagger.android.a aVar2 = (dagger.android.a) aVar.get();
            try {
                aVar2.create(obj).d(obj);
                return;
            } catch (ClassCastException e) {
                throw new DispatchingAndroidInjector$InvalidInjectorBindingException(androidx.compose.ui.node.B.i(aVar2.getClass().getCanonicalName(), " does not implement AndroidInjector.Factory<", obj.getClass().getCanonicalName(), SimpleComparison.GREATER_THAN_OPERATION), e);
            }
        }
        ArrayList arrayList = new ArrayList();
        for (Class<?> superclass = obj.getClass(); superclass != null; superclass = superclass.getSuperclass()) {
            if (map.containsKey(superclass.getCanonicalName())) {
                arrayList.add(superclass.getCanonicalName());
            }
        }
        throw new IllegalArgumentException(arrayList.isEmpty() ? android.support.v4.media.session.a.B("No injector factory bound for Class<", obj.getClass().getCanonicalName(), SimpleComparison.GREATER_THAN_OPERATION) : String.format("No injector factory bound for Class<%1$s>. Injector factories were bound for supertypes of %1$s: %2$s. Did you mean to bind an injector factory for the subtype?", obj.getClass().getCanonicalName(), arrayList));
    }

    @Override // io.reactivex.rxjava3.core.q
    public void onError(Throwable th) {
        ((io.reactivex.rxjava3.core.b) this.b).onError(th);
    }

    @Override // io.reactivex.rxjava3.core.q, com.google.android.gms.tasks.d
    public void onSuccess(Object obj) {
        ((io.reactivex.rxjava3.core.b) this.b).onComplete();
    }

    public C4636c(com.quizlet.quizletandroid.ui.common.images.capture.b remoteExerciseMapper) {
        this.a = 5;
        Intrinsics.checkNotNullParameter(remoteExerciseMapper, "remoteExerciseMapper");
        this.b = remoteExerciseMapper;
    }

    public C4636c(com.squareup.moshi.l jsonAdapter) {
        this.a = 6;
        Intrinsics.checkNotNullParameter(jsonAdapter, "jsonAdapter");
        this.b = jsonAdapter;
    }

    public C4636c(com.quizlet.remote.service.C service) {
        this.a = 7;
        Intrinsics.checkNotNullParameter(service, "service");
        this.b = service;
    }

    public C4636c(C4641h displayMetricsCreator) {
        this.a = 0;
        C4641h googleAdsWrapper = C4641h.b;
        Intrinsics.checkNotNullParameter(displayMetricsCreator, "displayMetricsCreator");
        Intrinsics.checkNotNullParameter(googleAdsWrapper, "googleAdsWrapper");
        this.b = displayMetricsCreator;
    }

    public C4636c(com.quizlet.quizletandroid.util.g loginBackstackManager) {
        this.a = 1;
        Intrinsics.checkNotNullParameter(loginBackstackManager, "loginBackstackManager");
        this.b = loginBackstackManager;
    }

    public C4636c(com.google.common.collect.C c) {
        this.a = 9;
        Object objUnmodifiableMap = com.google.common.collect.C.g;
        if (!c.isEmpty()) {
            int i = c.f;
            LinkedHashMap linkedHashMap = new LinkedHashMap(i < 3 ? i + 1 : i < 1073741824 ? (int) ((i / 0.75f) + 1.0f) : SubsamplingScaleImageView.TILE_SIZE_AUTO);
            linkedHashMap.putAll(objUnmodifiableMap);
            for (Map.Entry entry : c.entrySet()) {
                linkedHashMap.put(((Class) entry.getKey()).getName(), entry.getValue());
            }
            objUnmodifiableMap = Collections.unmodifiableMap(linkedHashMap);
        }
        this.b = objUnmodifiableMap;
    }
}

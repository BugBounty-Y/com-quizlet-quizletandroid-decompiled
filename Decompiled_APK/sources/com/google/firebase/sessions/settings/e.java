package com.google.firebase.sessions.settings;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3397u1;
import com.google.firebase.sessions.C3980b;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class e implements o {
    public final CoroutineContext a;
    public final com.google.firebase.installations.d b;
    public final C3980b c;
    public final g d;
    public final com.google.firebase.sessions.dagger.a e;
    public final kotlinx.coroutines.sync.c f;

    public e(CoroutineContext backgroundDispatcher, com.google.firebase.installations.d firebaseInstallationsApi, C3980b appInfo, g configsFetcher, com.google.firebase.sessions.dagger.a lazySettingsCache) {
        Intrinsics.checkNotNullParameter(backgroundDispatcher, "backgroundDispatcher");
        Intrinsics.checkNotNullParameter(firebaseInstallationsApi, "firebaseInstallationsApi");
        Intrinsics.checkNotNullParameter(appInfo, "appInfo");
        Intrinsics.checkNotNullParameter(configsFetcher, "configsFetcher");
        Intrinsics.checkNotNullParameter(lazySettingsCache, "lazySettingsCache");
        this.a = backgroundDispatcher;
        this.b = firebaseInstallationsApi;
        this.c = appInfo;
        this.d = configsFetcher;
        this.e = lazySettingsCache;
        this.f = kotlinx.coroutines.sync.d.a();
    }

    @Override // com.google.firebase.sessions.settings.o
    public final Boolean a() {
        h hVar = e().b;
        if (hVar != null) {
            return hVar.a;
        }
        Intrinsics.m("sessionConfigs");
        throw null;
    }

    @Override // com.google.firebase.sessions.settings.o
    public final kotlin.time.b b() {
        h hVar = e().b;
        if (hVar == null) {
            Intrinsics.m("sessionConfigs");
            throw null;
        }
        Integer num = hVar.c;
        if (num == null) {
            return null;
        }
        kotlin.time.a aVar = kotlin.time.b.b;
        return new kotlin.time.b(AbstractC3397u1.f(num.intValue(), kotlin.time.d.d));
    }

    @Override // com.google.firebase.sessions.settings.o
    public final Double c() {
        h hVar = e().b;
        if (hVar != null) {
            return hVar.b;
        }
        Intrinsics.m("sessionConfigs");
        throw null;
    }

    /* JADX WARN: Removed duplicated region for block: B:47:0x00c1 A[Catch: all -> 0x0052, TryCatch #0 {all -> 0x0052, blocks: (B:21:0x004e, B:45:0x00b7, B:47:0x00c1, B:48:0x00cb, B:51:0x0165, B:37:0x0093, B:39:0x009d, B:42:0x00a5), top: B:60:0x002c }] */
    /* JADX WARN: Removed duplicated region for block: B:48:0x00cb A[Catch: all -> 0x0052, TryCatch #0 {all -> 0x0052, blocks: (B:21:0x004e, B:45:0x00b7, B:47:0x00c1, B:48:0x00cb, B:51:0x0165, B:37:0x0093, B:39:0x009d, B:42:0x00a5), top: B:60:0x002c }] */
    /* JADX WARN: Removed duplicated region for block: B:7:0x001b  */
    /* JADX WARN: Type inference failed for: r6v0, types: [int] */
    @Override // com.google.firebase.sessions.settings.o
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object d(kotlin.coroutines.h r18) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 379
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.firebase.sessions.settings.e.d(kotlin.coroutines.h):java.lang.Object");
    }

    public final n e() {
        Object obj = this.e.get();
        Intrinsics.checkNotNullExpressionValue(obj, "lazySettingsCache.get()");
        return (n) obj;
    }
}

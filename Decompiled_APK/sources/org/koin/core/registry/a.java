package org.koin.core.registry;

import java.util.HashSet;
import java.util.concurrent.ConcurrentHashMap;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public static final org.koin.core.qualifier.a c;
    public final HashSet a;
    public final org.koin.core.scope.a b;

    static {
        Intrinsics.checkNotNullParameter("_root_", "name");
        c = new org.koin.core.qualifier.a("_root_");
    }

    public a(com.quizlet.data.repository.login.a _koin) {
        Intrinsics.checkNotNullParameter(_koin, "_koin");
        HashSet hashSet = new HashSet();
        this.a = hashSet;
        ConcurrentHashMap concurrentHashMap = new ConcurrentHashMap();
        org.koin.core.qualifier.a aVar = c;
        org.koin.core.scope.a aVar2 = new org.koin.core.scope.a(aVar, _koin);
        this.b = aVar2;
        hashSet.add(aVar);
        concurrentHashMap.put("_root_", aVar2);
    }
}

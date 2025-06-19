package com.quizlet.infra.legacysyncengine.datasources.factory;

import com.facebook.z;
import com.quizlet.generated.enums.G1;
import com.quizlet.infra.legacysyncengine.datasources.w;
import com.quizlet.infra.legacysyncengine.net.c;
import java.util.LinkedHashMap;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b {
    public final c a;
    public final com.quizlet.db.a b;
    public final long c;
    public final z d;
    public final LinkedHashMap e;

    public b(c loader, com.quizlet.db.a globalSharedPreferencesManager, long j, z setInSelectedTermsModeCache) {
        Intrinsics.checkNotNullParameter(loader, "loader");
        Intrinsics.checkNotNullParameter(globalSharedPreferencesManager, "globalSharedPreferencesManager");
        Intrinsics.checkNotNullParameter(setInSelectedTermsModeCache, "setInSelectedTermsModeCache");
        this.a = loader;
        this.b = globalSharedPreferencesManager;
        this.c = j;
        this.d = setInSelectedTermsModeCache;
        this.e = new LinkedHashMap();
    }

    public final w a(long j) {
        LinkedHashMap linkedHashMap = this.e;
        Long lValueOf = Long.valueOf(j);
        Object obj = linkedHashMap.get(lValueOf);
        if (obj == null) {
            w wVar = new w(this.a, j, this.c, this.d.a(j, G1.SET), this.b.a(j));
            linkedHashMap.put(lValueOf, wVar);
            obj = wVar;
        }
        return (w) obj;
    }
}

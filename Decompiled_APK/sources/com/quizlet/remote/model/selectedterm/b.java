package com.quizlet.remote.model.selectedterm;

import com.squareup.moshi.D;
import com.squareup.moshi.l;
import com.squareup.moshi.p;
import com.squareup.moshi.w;
import java.util.Map;
import java.util.Set;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b extends l {
    public final l a;
    public final l b;

    public b(D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        moshi.getClass();
        Set set = com.squareup.moshi.internal.b.a;
        this.a = moshi.a(RemoteSelectedTerm.class, set, null);
        this.b = moshi.a(RemoteUnselectedTerm.class, set, null);
    }

    @Override // com.squareup.moshi.l
    public final Object a(p jsonReader) {
        Intrinsics.checkNotNullParameter(jsonReader, "jsonReader");
        Object objD0 = jsonReader.d0();
        Intrinsics.e(objD0, "null cannot be cast to non-null type kotlin.collections.Map<*, *>");
        Map map = (Map) objD0;
        return map.containsKey("isDeleted") ? (a) this.b.c(map) : (a) this.a.c(map);
    }

    @Override // com.squareup.moshi.l
    public final void g(w jsonWriter, Object obj) {
        a aVar = (a) obj;
        Intrinsics.checkNotNullParameter(jsonWriter, "jsonWriter");
        if (aVar instanceof RemoteSelectedTerm) {
            this.a.g(jsonWriter, aVar);
        } else if (aVar instanceof RemoteUnselectedTerm) {
            this.b.g(jsonWriter, aVar);
        }
    }
}

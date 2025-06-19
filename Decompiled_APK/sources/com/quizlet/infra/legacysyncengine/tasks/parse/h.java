package com.quizlet.infra.legacysyncengine.tasks.parse;

import com.quizlet.api.model.PagingInfo;
import java.util.HashSet;
import java.util.Map;

/* loaded from: classes3.dex */
public final class h {
    public final Map a;
    public final Map b;
    public final com.quizlet.infra.legacysyncengine.net.request.i c;
    public final PagingInfo d;

    public h(Map map, Map map2, com.quizlet.infra.legacysyncengine.net.request.i iVar, PagingInfo pagingInfo) {
        this.a = map;
        this.b = map2;
        this.c = iVar;
        this.d = pagingInfo;
    }

    public final HashSet a() {
        HashSet hashSet = new HashSet();
        hashSet.addAll(this.a.keySet());
        hashSet.addAll(this.b.keySet());
        return hashSet;
    }
}

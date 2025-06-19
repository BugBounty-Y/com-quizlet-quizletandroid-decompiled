package com.google.android.datatransport.runtime.backends;

import android.content.Context;
import com.google.android.datatransport.cct.CctBackendFactory;
import java.util.HashMap;

/* loaded from: classes2.dex */
public final class f {
    public final com.quizlet.data.repository.searchexplanations.c a;
    public final d b;
    public final HashMap c;

    public f(Context context, d dVar) {
        com.quizlet.data.repository.searchexplanations.c cVar = new com.quizlet.data.repository.searchexplanations.c(context, 7);
        this.c = new HashMap();
        this.a = cVar;
        this.b = dVar;
    }

    public final synchronized h a(String str) {
        if (this.c.containsKey(str)) {
            return (h) this.c.get(str);
        }
        CctBackendFactory cctBackendFactoryF = this.a.f(str);
        if (cctBackendFactoryF == null) {
            return null;
        }
        d dVar = this.b;
        h hVarCreate = cctBackendFactoryF.create(new b(dVar.a, dVar.b, dVar.c, str));
        this.c.put(str, hVarCreate);
        return hVarCreate;
    }
}

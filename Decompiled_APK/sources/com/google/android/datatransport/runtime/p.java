package com.google.android.datatransport.runtime;

import java.util.HashMap;

/* loaded from: classes2.dex */
public final class p {
    public final i a;
    public final String b;
    public final com.google.android.datatransport.c c;
    public final com.google.android.datatransport.e d;
    public final q e;

    public p(i iVar, String str, com.google.android.datatransport.c cVar, com.google.android.datatransport.e eVar, q qVar) {
        this.a = iVar;
        this.b = str;
        this.c = cVar;
        this.d = eVar;
        this.e = qVar;
    }

    public final void a(com.google.android.datatransport.a aVar, com.google.android.datatransport.g gVar) {
        i iVar = this.a;
        String str = this.b;
        if (str == null) {
            throw new NullPointerException("Null transportName");
        }
        com.google.android.datatransport.e eVar = this.d;
        if (eVar == null) {
            throw new NullPointerException("Null transformer");
        }
        com.google.android.datatransport.c cVar = this.c;
        q qVar = this.e;
        i iVarB = iVar.b(aVar.b);
        androidx.compose.runtime.internal.j jVar = new androidx.compose.runtime.internal.j();
        jVar.f = new HashMap();
        jVar.d = Long.valueOf(qVar.a.e());
        jVar.e = Long.valueOf(qVar.b.e());
        jVar.a = str;
        jVar.c = new k(cVar, (byte[]) eVar.apply(aVar.a));
        jVar.b = null;
        com.google.android.datatransport.b bVar = aVar.c;
        if (bVar != null) {
            jVar.g = bVar.a;
        }
        h hVarB = jVar.b();
        com.google.android.datatransport.runtime.scheduling.a aVar2 = (com.google.android.datatransport.runtime.scheduling.a) qVar.c;
        aVar2.getClass();
        aVar2.b.execute(new androidx.camera.camera2.internal.compat.b(aVar2, iVarB, gVar, hVarB, 9));
    }
}

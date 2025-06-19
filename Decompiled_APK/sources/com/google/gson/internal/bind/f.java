package com.google.gson.internal.bind;

import androidx.compose.ui.node.B;
import com.google.android.gms.measurement.internal.Z;
import com.google.gson.JsonSyntaxException;
import com.google.gson.q;
import java.io.IOException;
import java.lang.reflect.Type;
import java.util.Map;

/* loaded from: classes2.dex */
public final class f extends q {
    public final d a;
    public final d b;
    public final com.google.gson.internal.n c;

    public f(c cVar, com.google.gson.k kVar, Type type, q qVar, Type type2, q qVar2, com.google.gson.internal.n nVar) {
        this.a = new d(kVar, qVar, type);
        this.b = new d(kVar, qVar2, type2);
        this.c = nVar;
    }

    @Override // com.google.gson.q
    public final Object a(com.google.gson.stream.a aVar) throws IOException {
        int iL0 = aVar.l0();
        if (iL0 == 9) {
            aVar.a0();
            return null;
        }
        Map map = (Map) this.c.E();
        d dVar = this.b;
        d dVar2 = this.a;
        q qVar = (q) dVar.b;
        q qVar2 = (q) dVar2.b;
        if (iL0 == 1) {
            aVar.a();
            while (aVar.q()) {
                aVar.a();
                Object objA = qVar2.a(aVar);
                if (map.put(objA, qVar.a(aVar)) != null) {
                    throw new JsonSyntaxException(B.e(objA, "duplicate key: "));
                }
                aVar.j();
            }
            aVar.j();
            return map;
        }
        aVar.d();
        while (aVar.q()) {
            com.quizlet.shared.usecase.folderstudymaterials.c.c.getClass();
            int i = aVar.h;
            if (i == 0) {
                i = aVar.i();
            }
            if (i == 13) {
                aVar.h = 9;
            } else if (i == 12) {
                aVar.h = 8;
            } else {
                if (i != 14) {
                    throw new IllegalStateException("Expected a name but was " + Z.s(aVar.l0()) + aVar.y());
                }
                aVar.h = 10;
            }
            Object objA2 = qVar2.a(aVar);
            if (map.put(objA2, qVar.a(aVar)) != null) {
                throw new JsonSyntaxException(B.e(objA2, "duplicate key: "));
            }
        }
        aVar.l();
        return map;
    }
}

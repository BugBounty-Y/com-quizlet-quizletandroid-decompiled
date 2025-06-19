package androidx.compose.runtime.saveable;

import androidx.collection.I;
import androidx.collection.S;
import androidx.compose.runtime.C0775b0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.runtime.V;
import androidx.compose.runtime.X0;
import com.comscore.streaming.ContentType;
import java.util.Map;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class f implements c {
    public static final com.quizlet.data.repository.explanations.myexplanations.a e;
    public final Map a;
    public final I b;
    public i c;
    public final C0775b0 d;

    static {
        d dVar = d.b;
        e eVar = e.b;
        com.quizlet.data.repository.explanations.myexplanations.a aVar = m.a;
        e = new com.quizlet.data.repository.explanations.myexplanations.a(dVar, false, eVar, 3);
    }

    public f(Map map) {
        this.a = map;
        long[] jArr = S.a;
        this.b = new I();
        this.d = new C0775b0(this, 7);
    }

    @Override // androidx.compose.runtime.saveable.c
    public final void e(Object obj, androidx.compose.runtime.internal.d dVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(-1198538093);
        c0814p.a0(obj);
        Object objI = c0814p.I();
        V v = C0804k.a;
        if (objI == v) {
            C0775b0 c0775b0 = this.d;
            if (!((Boolean) c0775b0.invoke(obj)).booleanValue()) {
                throw new IllegalArgumentException(("Type of the key " + obj + " is not supported. On Android you can only use types which can be stored inside the Bundle.").toString());
            }
            Map map = (Map) this.a.get(obj);
            X0 x0 = k.a;
            j jVar = new j(map, c0775b0);
            c0814p.i0(jVar);
            objI = jVar;
        }
        i iVar = (i) objI;
        C0776c.a(k.a.a(iVar), dVar, c0814p, (i & ContentType.LONG_FORM_ON_DEMAND) | 8);
        Unit unit = Unit.a;
        boolean zH = c0814p.h(this) | c0814p.h(obj) | c0814p.h(iVar);
        Object objI2 = c0814p.I();
        if (zH || objI2 == v) {
            objI2 = new androidx.activity.compose.g(this, obj, iVar, 21);
            c0814p.i0(objI2);
        }
        C0776c.d(unit, (Function1) objI2, c0814p);
        if (c0814p.x && c0814p.F.i == c0814p.y) {
            c0814p.y = -1;
            c0814p.x = false;
        }
        c0814p.p(false);
        c0814p.p(false);
    }

    @Override // androidx.compose.runtime.saveable.c
    public final void f(Object obj) {
        if (this.b.h(obj) == null) {
            this.a.remove(obj);
        }
    }
}

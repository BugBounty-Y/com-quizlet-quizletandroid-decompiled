package androidx.constraintlayout.core.state;

import java.util.HashMap;

/* loaded from: classes.dex */
public final class k {
    public final androidx.constraintlayout.core.widgets.e a;
    public int b;
    public int c;
    public float d;
    public float e;
    public float f;
    public float g;
    public float h;
    public float i;
    public float j;
    public float k;
    public float l;
    public float m;
    public float n;
    public int o;
    public final HashMap p;

    public k(androidx.constraintlayout.core.widgets.e eVar) {
        this.a = null;
        this.b = 0;
        this.c = 0;
        this.d = Float.NaN;
        this.e = Float.NaN;
        this.f = Float.NaN;
        this.g = Float.NaN;
        this.h = Float.NaN;
        this.i = Float.NaN;
        this.j = Float.NaN;
        this.k = Float.NaN;
        this.l = Float.NaN;
        this.m = Float.NaN;
        this.n = Float.NaN;
        this.o = 0;
        this.p = new HashMap();
        this.a = eVar;
    }

    public final void a(k kVar) {
        if (kVar == null) {
            return;
        }
        this.d = kVar.d;
        this.e = kVar.e;
        this.f = kVar.f;
        this.g = kVar.g;
        this.h = kVar.h;
        this.i = kVar.i;
        this.j = kVar.j;
        this.k = kVar.k;
        this.l = kVar.l;
        this.m = kVar.m;
        this.n = kVar.n;
        this.o = kVar.o;
        HashMap map = this.p;
        map.clear();
        for (androidx.constraintlayout.core.motion.a aVar : kVar.p.values()) {
            String str = aVar.a;
            androidx.constraintlayout.core.motion.a aVar2 = new androidx.constraintlayout.core.motion.a();
            aVar2.c = Integer.MIN_VALUE;
            aVar2.d = Float.NaN;
            aVar2.a = str;
            aVar2.b = aVar.b;
            aVar2.c = aVar.c;
            aVar2.d = aVar.d;
            map.put(str, aVar2);
        }
    }

    public k(k kVar) {
        this.a = null;
        this.b = 0;
        this.c = 0;
        this.d = Float.NaN;
        this.e = Float.NaN;
        this.f = Float.NaN;
        this.g = Float.NaN;
        this.h = Float.NaN;
        this.i = Float.NaN;
        this.j = Float.NaN;
        this.k = Float.NaN;
        this.l = Float.NaN;
        this.m = Float.NaN;
        this.n = Float.NaN;
        this.o = 0;
        this.p = new HashMap();
        this.a = kVar.a;
        this.b = kVar.b;
        this.c = kVar.c;
        a(kVar);
    }
}

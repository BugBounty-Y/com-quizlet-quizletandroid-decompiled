package androidx.compose.ui.graphics.colorspace;

import androidx.collection.AbstractC0214l;
import androidx.collection.C0223v;

/* loaded from: classes.dex */
public abstract class h {
    public static final C0223v a;

    static {
        q qVar = d.c;
        int i = qVar.c;
        e eVar = new e(qVar, qVar, 1);
        l lVar = d.t;
        int i2 = lVar.c << 6;
        int i3 = qVar.c;
        int i4 = i2 | i3;
        g gVar = new g(qVar, lVar, 0);
        int i5 = (i3 << 6) | lVar.c;
        g gVar2 = new g(lVar, qVar, 0);
        C0223v c0223v = AbstractC0214l.a;
        C0223v c0223v2 = new C0223v();
        c0223v2.h(i | (i << 6), eVar);
        c0223v2.h(i4, gVar);
        c0223v2.h(i5, gVar2);
        a = c0223v2;
    }
}

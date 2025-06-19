package androidx.compose.foundation.layout;

import androidx.compose.animation.C0281h;
import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes.dex */
public abstract class K0 {
    public static final FillElement a = new FillElement(1.0f, 2);
    public static final FillElement b = new FillElement(1.0f, 1);
    public static final FillElement c = new FillElement(1.0f, 3);
    public static final WrapContentElement d;
    public static final WrapContentElement e;
    public static final WrapContentElement f;
    public static final WrapContentElement g;
    public static final WrapContentElement h;
    public static final WrapContentElement i;

    static {
        androidx.compose.ui.g gVar = androidx.compose.ui.b.n;
        d = new WrapContentElement(2, new C0281h(gVar, 6), gVar);
        androidx.compose.ui.g gVar2 = androidx.compose.ui.b.m;
        e = new WrapContentElement(2, new C0281h(gVar2, 6), gVar2);
        androidx.compose.ui.h hVar = androidx.compose.ui.b.k;
        f = new WrapContentElement(1, new C0281h(hVar, 4), hVar);
        androidx.compose.ui.h hVar2 = androidx.compose.ui.b.j;
        g = new WrapContentElement(1, new C0281h(hVar2, 4), hVar2);
        androidx.compose.ui.i iVar = androidx.compose.ui.b.e;
        h = new WrapContentElement(3, new C0281h(iVar, 5), iVar);
        androidx.compose.ui.i iVar2 = androidx.compose.ui.b.a;
        i = new WrapContentElement(3, new C0281h(iVar2, 5), iVar2);
    }

    public static final androidx.compose.ui.q a(androidx.compose.ui.q qVar, float f2, float f3) {
        return qVar.g(new UnspecifiedConstraintsElement(f2, f3));
    }

    public static /* synthetic */ androidx.compose.ui.q b(androidx.compose.ui.q qVar, float f2, float f3, int i2) {
        if ((i2 & 1) != 0) {
            f2 = Float.NaN;
        }
        if ((i2 & 2) != 0) {
            f3 = Float.NaN;
        }
        return a(qVar, f2, f3);
    }

    public static final androidx.compose.ui.q c(androidx.compose.ui.q qVar, float f2) {
        return qVar.g(f2 == 1.0f ? a : new FillElement(f2, 2));
    }

    public static final androidx.compose.ui.q d(androidx.compose.ui.q qVar, float f2) {
        return qVar.g(new SizeElement(DefinitionKt.NO_Float_VALUE, f2, DefinitionKt.NO_Float_VALUE, f2, true, 5));
    }

    public static final androidx.compose.ui.q e(androidx.compose.ui.q qVar, float f2, float f3) {
        return qVar.g(new SizeElement(DefinitionKt.NO_Float_VALUE, f2, DefinitionKt.NO_Float_VALUE, f3, true, 5));
    }

    public static /* synthetic */ androidx.compose.ui.q f(androidx.compose.ui.q qVar, float f2, float f3, int i2) {
        if ((i2 & 1) != 0) {
            f2 = Float.NaN;
        }
        if ((i2 & 2) != 0) {
            f3 = Float.NaN;
        }
        return e(qVar, f2, f3);
    }

    public static final androidx.compose.ui.q g(androidx.compose.ui.q qVar, float f2) {
        return qVar.g(new SizeElement(DefinitionKt.NO_Float_VALUE, f2, DefinitionKt.NO_Float_VALUE, f2, false, 5));
    }

    public static final androidx.compose.ui.q h(androidx.compose.ui.q qVar) {
        float f2 = androidx.compose.material3.tokens.w.a;
        return qVar.g(new SizeElement(f2, f2, f2, f2, false));
    }

    public static final androidx.compose.ui.q i(androidx.compose.ui.q qVar, float f2, float f3) {
        return qVar.g(new SizeElement(f2, f3, f2, f3, false));
    }

    public static androidx.compose.ui.q j(androidx.compose.ui.q qVar, float f2, float f3, float f4, float f5, int i2) {
        return qVar.g(new SizeElement(f2, (i2 & 2) != 0 ? Float.NaN : f3, (i2 & 4) != 0 ? Float.NaN : f4, (i2 & 8) != 0 ? Float.NaN : f5, false));
    }

    public static final androidx.compose.ui.q k(androidx.compose.ui.q qVar, float f2) {
        return qVar.g(new SizeElement(f2, f2, f2, f2, true));
    }

    public static final androidx.compose.ui.q l(androidx.compose.ui.q qVar, float f2, float f3) {
        return qVar.g(new SizeElement(f2, f3, f2, f3, true));
    }

    public static final androidx.compose.ui.q m(androidx.compose.ui.q qVar, float f2, float f3, float f4, float f5) {
        return qVar.g(new SizeElement(f2, f3, f4, f5, true));
    }

    public static /* synthetic */ androidx.compose.ui.q n(androidx.compose.ui.q qVar, float f2, float f3, float f4, float f5, int i2) {
        if ((i2 & 1) != 0) {
            f2 = Float.NaN;
        }
        if ((i2 & 2) != 0) {
            f3 = Float.NaN;
        }
        if ((i2 & 4) != 0) {
            f4 = Float.NaN;
        }
        if ((i2 & 8) != 0) {
            f5 = Float.NaN;
        }
        return m(qVar, f2, f3, f4, f5);
    }

    public static final androidx.compose.ui.q o(androidx.compose.ui.q qVar, float f2) {
        return qVar.g(new SizeElement(f2, DefinitionKt.NO_Float_VALUE, f2, DefinitionKt.NO_Float_VALUE, true, 10));
    }

    public static final androidx.compose.ui.q p(androidx.compose.ui.q qVar, float f2, float f3) {
        return qVar.g(new SizeElement(f2, DefinitionKt.NO_Float_VALUE, f3, DefinitionKt.NO_Float_VALUE, true, 10));
    }

    public static /* synthetic */ androidx.compose.ui.q q(androidx.compose.ui.q qVar, float f2, float f3, int i2) {
        if ((i2 & 1) != 0) {
            f2 = Float.NaN;
        }
        if ((i2 & 2) != 0) {
            f3 = Float.NaN;
        }
        return p(qVar, f2, f3);
    }

    public static androidx.compose.ui.q r(androidx.compose.ui.q qVar, int i2) {
        androidx.compose.ui.h hVar = androidx.compose.ui.b.k;
        return qVar.g(hVar.equals(hVar) ? f : hVar.equals(androidx.compose.ui.b.j) ? g : new WrapContentElement(1, new C0281h(hVar, 4), hVar));
    }

    public static androidx.compose.ui.q s(androidx.compose.ui.q qVar, androidx.compose.ui.i iVar, int i2) {
        int i3 = i2 & 1;
        androidx.compose.ui.i iVar2 = androidx.compose.ui.b.e;
        if (i3 != 0) {
            iVar = iVar2;
        }
        return qVar.g(iVar.equals(iVar2) ? h : iVar.equals(androidx.compose.ui.b.a) ? i : new WrapContentElement(3, new C0281h(iVar, 5), iVar));
    }

    public static androidx.compose.ui.q t(androidx.compose.ui.q qVar, int i2) {
        androidx.compose.ui.g gVar = androidx.compose.ui.b.o;
        int i3 = i2 & 1;
        androidx.compose.ui.g gVar2 = androidx.compose.ui.b.n;
        if (i3 != 0) {
            gVar = gVar2;
        }
        return qVar.g(gVar.equals(gVar2) ? d : gVar.equals(androidx.compose.ui.b.m) ? e : new WrapContentElement(2, new C0281h(gVar, 6), gVar));
    }
}

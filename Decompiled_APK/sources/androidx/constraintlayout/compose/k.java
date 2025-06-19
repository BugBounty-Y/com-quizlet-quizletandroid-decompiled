package androidx.constraintlayout.compose;

import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.camera.camera2.internal.C0132i;
import com.google.android.gms.internal.mlkit_vision_barcode.L5;
import java.util.ArrayList;
import java.util.HashMap;

/* loaded from: classes.dex */
public final class k {
    public C0132i a;
    public boolean b = true;
    public final HashMap c;
    public final HashMap d;
    public final HashMap e;
    public final androidx.constraintlayout.core.state.b f;
    public int g;
    public final ArrayList h;
    public final ArrayList i;
    public boolean j;
    public final androidx.compose.ui.unit.b k;
    public long l;

    public k(androidx.compose.ui.unit.b bVar) {
        HashMap map = new HashMap();
        this.c = map;
        this.d = new HashMap();
        this.e = new HashMap();
        androidx.constraintlayout.core.state.b bVar2 = new androidx.constraintlayout.core.state.b(this);
        this.f = bVar2;
        this.g = 0;
        this.h = new ArrayList();
        this.i = new ArrayList();
        this.j = true;
        bVar2.a = 0;
        map.put(0, bVar2);
        this.k = bVar;
        this.l = L5.b(0, 0, 15);
        this.a = new C0132i(this, 14);
    }

    public final void a(Object obj) {
        this.h.add(obj);
        this.j = true;
    }

    public final androidx.constraintlayout.core.state.b b(Object obj) {
        HashMap map = this.c;
        androidx.constraintlayout.core.state.h hVar = (androidx.constraintlayout.core.state.h) map.get(obj);
        androidx.constraintlayout.core.state.h hVar2 = hVar;
        if (hVar == null) {
            androidx.constraintlayout.core.state.b bVar = new androidx.constraintlayout.core.state.b(this);
            map.put(obj, bVar);
            bVar.a = obj;
            hVar2 = bVar;
        }
        if (hVar2 instanceof androidx.constraintlayout.core.state.b) {
            return (androidx.constraintlayout.core.state.b) hVar2;
        }
        return null;
    }

    public final int c(Float f) {
        return Math.round(f.floatValue());
    }

    public final androidx.constraintlayout.core.state.helpers.g d(int i, String str) {
        androidx.constraintlayout.core.state.b bVarB = b(str);
        Object obj = bVarB.c;
        if (obj == null || !(obj instanceof androidx.constraintlayout.core.state.helpers.g)) {
            androidx.constraintlayout.core.state.helpers.g gVar = new androidx.constraintlayout.core.state.helpers.g(this);
            gVar.b = i;
            gVar.g = str;
            bVarB.c = gVar;
            bVarB.a(gVar.b());
        }
        return (androidx.constraintlayout.core.state.helpers.g) bVarB.c;
    }

    public final androidx.constraintlayout.core.state.g e(int i) {
        androidx.constraintlayout.core.state.g hVar;
        StringBuilder sb = new StringBuilder("__HELPER_KEY_");
        int i2 = this.g;
        this.g = i2 + 1;
        String strR = android.support.v4.media.session.a.r(sb, i2, "__");
        HashMap map = this.d;
        androidx.constraintlayout.core.state.g gVar = (androidx.constraintlayout.core.state.g) map.get(strR);
        androidx.constraintlayout.core.state.g gVar2 = gVar;
        if (gVar == null) {
            int i3 = 4;
            switch (AbstractC0147y.k(i)) {
                case 0:
                    hVar = new androidx.constraintlayout.core.state.helpers.h(this, 1);
                    break;
                case 1:
                    hVar = new androidx.constraintlayout.core.state.helpers.i(this, 2);
                    break;
                case 2:
                    androidx.constraintlayout.core.state.helpers.a aVar = new androidx.constraintlayout.core.state.helpers.a(this, i3, 0);
                    aVar.o0 = 0.5f;
                    hVar = aVar;
                    break;
                case 3:
                    androidx.constraintlayout.core.state.helpers.a aVar2 = new androidx.constraintlayout.core.state.helpers.a(this, i3, 1);
                    aVar2.o0 = 0.5f;
                    hVar = aVar2;
                    break;
                case 4:
                    hVar = new androidx.constraintlayout.core.state.helpers.b(this, 5);
                    break;
                case 5:
                default:
                    hVar = new androidx.constraintlayout.core.state.g(this, i);
                    break;
                case 6:
                case 7:
                    hVar = new androidx.constraintlayout.core.state.helpers.e(this, i);
                    break;
                case 8:
                case 9:
                case 10:
                    hVar = new androidx.constraintlayout.core.state.helpers.f(this, i);
                    break;
            }
            hVar.a = strR;
            map.put(strR, hVar);
            gVar2 = hVar;
        }
        return gVar2;
    }
}

package androidx.camera.core.streamsharing;

import android.graphics.Matrix;
import android.graphics.Rect;
import android.graphics.RectF;
import android.util.Pair;
import android.util.Rational;
import android.util.Size;
import androidx.camera.camera2.internal.K;
import androidx.camera.camera2.internal.s0;
import androidx.camera.core.L;
import androidx.camera.core.S;
import androidx.camera.core.X;
import androidx.camera.core.impl.A0;
import androidx.camera.core.impl.DeferrableSurface$SurfaceClosedException;
import androidx.camera.core.impl.InterfaceC0185y;
import androidx.camera.core.impl.J;
import androidx.camera.core.impl.P;
import androidx.camera.core.impl.o0;
import androidx.camera.core.impl.q0;
import androidx.camera.core.k0;
import androidx.camera.core.l0;
import androidx.camera.core.processing.j;
import androidx.camera.core.processing.k;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/* loaded from: classes.dex */
public final class g implements k0 {
    public final HashSet a;
    public final K e;
    public final InterfaceC0185y f;
    public final InterfaceC0185y g;
    public final HashSet i;
    public final HashMap j;
    public final b k;
    public final b l;
    public final HashMap b = new HashMap();
    public final HashMap c = new HashMap();
    public final HashMap d = new HashMap();
    public final S h = new S(this, 2);

    public g(InterfaceC0185y interfaceC0185y, InterfaceC0185y interfaceC0185y2, HashSet hashSet, K k, s0 s0Var) {
        this.f = interfaceC0185y;
        this.g = interfaceC0185y2;
        this.e = k;
        this.a = hashSet;
        HashMap map = new HashMap();
        Iterator it2 = hashSet.iterator();
        while (it2.hasNext()) {
            l0 l0Var = (l0) it2.next();
            map.put(l0Var, l0Var.l(interfaceC0185y.n(), null, l0Var.e(true, k)));
        }
        this.j = map;
        HashSet hashSet2 = new HashSet(map.values());
        this.i = hashSet2;
        this.k = new b(interfaceC0185y, hashSet2);
        if (this.g != null) {
            this.l = new b(this.g, hashSet2);
        }
        Iterator it3 = hashSet.iterator();
        while (it3.hasNext()) {
            l0 l0Var2 = (l0) it3.next();
            this.d.put(l0Var2, Boolean.FALSE);
            this.c.put(l0Var2, new f(interfaceC0185y, this, s0Var));
        }
    }

    public static void q(k kVar, J j, q0 q0Var) {
        kVar.d();
        try {
            com.google.android.gms.internal.mlkit_vision_barcode.S.d();
            kVar.a();
            j jVar = kVar.l;
            Objects.requireNonNull(jVar);
            jVar.g(j, new androidx.camera.core.processing.g(jVar, 0));
        } catch (DeferrableSurface$SurfaceClosedException unused) {
            o0 o0Var = q0Var.f;
            if (o0Var != null) {
                o0Var.a(q0Var);
            }
        }
    }

    public static J r(l0 l0Var) {
        List listB = l0Var instanceof L ? l0Var.m.b() : Collections.unmodifiableList(l0Var.m.g.a);
        AbstractC3242q6.h(null, listB.size() <= 1);
        if (listB.size() == 1) {
            return (J) listB.get(0);
        }
        return null;
    }

    @Override // androidx.camera.core.k0
    public final void c(l0 l0Var) {
        com.google.android.gms.internal.mlkit_vision_barcode.S.d();
        if (s(l0Var)) {
            return;
        }
        this.d.put(l0Var, Boolean.TRUE);
        J jR = r(l0Var);
        if (jR != null) {
            k kVar = (k) this.b.get(l0Var);
            Objects.requireNonNull(kVar);
            q(kVar, jR, l0Var.m);
        }
    }

    @Override // androidx.camera.core.k0
    public final void d(l0 l0Var) {
        J jR;
        com.google.android.gms.internal.mlkit_vision_barcode.S.d();
        k kVar = (k) this.b.get(l0Var);
        Objects.requireNonNull(kVar);
        if (s(l0Var) && (jR = r(l0Var)) != null) {
            q(kVar, jR, l0Var.m);
        }
    }

    @Override // androidx.camera.core.k0
    public final void e(l0 l0Var) {
        com.google.android.gms.internal.mlkit_vision_barcode.S.d();
        if (s(l0Var)) {
            k kVar = (k) this.b.get(l0Var);
            Objects.requireNonNull(kVar);
            J jR = r(l0Var);
            if (jR != null) {
                q(kVar, jR, l0Var.m);
                return;
            }
            com.google.android.gms.internal.mlkit_vision_barcode.S.d();
            kVar.a();
            kVar.l.a();
        }
    }

    @Override // androidx.camera.core.k0
    public final void o(l0 l0Var) {
        com.google.android.gms.internal.mlkit_vision_barcode.S.d();
        if (s(l0Var)) {
            this.d.put(l0Var, Boolean.FALSE);
            k kVar = (k) this.b.get(l0Var);
            Objects.requireNonNull(kVar);
            com.google.android.gms.internal.mlkit_vision_barcode.S.d();
            kVar.a();
            kVar.l.a();
        }
    }

    public final androidx.camera.core.processing.util.b p(l0 l0Var, b bVar, InterfaceC0185y interfaceC0185y, k kVar, int i, boolean z) {
        Size size;
        Size sizeD;
        int iG = interfaceC0185y.n().g(i);
        Matrix matrix = kVar.b;
        RectF rectF = androidx.camera.core.impl.utils.f.a;
        float[] fArr = {DefinitionKt.NO_Float_VALUE, 1.0f, 1.0f, DefinitionKt.NO_Float_VALUE};
        matrix.mapVectors(fArr);
        float f = fArr[0];
        float f2 = fArr[1];
        float f3 = fArr[2];
        float f4 = fArr[3];
        float f5 = (f2 * f4) + (f * f3);
        float f6 = (f * f4) - (f2 * f3);
        float f7 = (f4 * f4) + (f3 * f3);
        boolean z2 = false;
        double dSqrt = Math.sqrt((f2 * f2) + (f * f)) * Math.sqrt(f7);
        boolean z3 = ((float) Math.toDegrees(Math.atan2(((double) f6) / dSqrt, ((double) f5) / dSqrt))) > DefinitionKt.NO_Float_VALUE;
        A0 a0 = (A0) this.j.get(l0Var);
        Objects.requireNonNull(a0);
        kVar.b.getValues(new float[9]);
        int iF = androidx.camera.core.impl.utils.f.f((int) Math.round(Math.atan2(r7[3], r7[0]) * 57.29577951308232d));
        bVar.getClass();
        boolean zB = androidx.camera.core.impl.utils.f.b(iF);
        Rect rectA = kVar.d;
        if (zB) {
            rectA = new Rect(rectA.top, rectA.left, rectA.bottom, rectA.right);
            z2 = true;
        }
        if (z) {
            sizeD = androidx.camera.core.impl.utils.f.d(rectA);
            Iterator it2 = bVar.b(a0).iterator();
            while (true) {
                if (!it2.hasNext()) {
                    break;
                }
                Size sizeD2 = androidx.camera.core.impl.utils.f.d(b.a((Size) it2.next(), sizeD));
                if (!b.c(sizeD2, sizeD)) {
                    sizeD = sizeD2;
                    break;
                }
            }
        } else {
            Size sizeD3 = androidx.camera.core.impl.utils.f.d(rectA);
            List listB = bVar.b(a0);
            Iterator it3 = listB.iterator();
            while (true) {
                if (!it3.hasNext()) {
                    Iterator it4 = listB.iterator();
                    while (true) {
                        if (!it4.hasNext()) {
                            size = sizeD3;
                            break;
                        }
                        Size size2 = (Size) it4.next();
                        if (!b.c(size2, sizeD3)) {
                            size = size2;
                            break;
                        }
                    }
                } else {
                    size = (Size) it3.next();
                    Rational rationalG = androidx.camera.core.impl.utils.b.a;
                    if (!androidx.camera.core.impl.utils.b.a(rationalG, sizeD3)) {
                        rationalG = androidx.camera.core.impl.utils.b.c;
                        if (!androidx.camera.core.impl.utils.b.a(rationalG, sizeD3)) {
                            rationalG = b.g(sizeD3);
                        }
                    }
                    if (!bVar.d(rationalG, size) && !b.c(size, sizeD3)) {
                        break;
                    }
                }
            }
            rectA = b.a(sizeD3, size);
            sizeD = size;
        }
        Pair pair = new Pair(rectA, sizeD);
        Rect rect = (Rect) pair.first;
        Size size3 = (Size) pair.second;
        if (z2) {
            Size size4 = new Size(size3.getHeight(), size3.getWidth());
            rect = new Rect(rect.top, rect.left, rect.bottom, rect.right);
            size3 = size4;
        }
        Pair pair2 = new Pair(rect, size3);
        Rect rect2 = (Rect) pair2.first;
        Size size5 = (Size) pair2.second;
        int iG2 = this.f.n().g(((P) l0Var.f).v());
        f fVar = (f) this.c.get(l0Var);
        Objects.requireNonNull(fVar);
        fVar.c.c = iG2;
        int iF2 = androidx.camera.core.impl.utils.f.f((kVar.i + iG2) - iG);
        return new androidx.camera.core.processing.util.b(UUID.randomUUID(), l0Var instanceof X ? 1 : l0Var instanceof L ? 4 : 2, l0Var instanceof L ? 256 : 34, rect2, androidx.camera.core.impl.utils.f.e(size5, iF2), iF2, l0Var.k(interfaceC0185y) ^ z3);
    }

    public final boolean s(l0 l0Var) {
        Boolean bool = (Boolean) this.d.get(l0Var);
        Objects.requireNonNull(bool);
        return bool.booleanValue();
    }

    public final void t(HashMap map) {
        HashMap map2 = this.b;
        map2.clear();
        map2.putAll(map);
        for (Map.Entry entry : map2.entrySet()) {
            l0 l0Var = (l0) entry.getKey();
            k kVar = (k) entry.getValue();
            l0Var.y(kVar.d);
            l0Var.x(kVar.b);
            l0Var.g = l0Var.v(kVar.g, null);
            l0Var.o();
        }
    }
}

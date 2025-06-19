package androidx.camera.core.internal;

import android.graphics.Matrix;
import android.graphics.Rect;
import android.graphics.RectF;
import android.util.Log;
import android.util.Pair;
import android.util.Range;
import android.util.Rational;
import android.util.Size;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.camera.camera2.internal.K;
import androidx.camera.camera2.internal.f0;
import androidx.camera.core.C0196t;
import androidx.camera.core.I;
import androidx.camera.core.InterfaceC0188k;
import androidx.camera.core.L;
import androidx.camera.core.Q;
import androidx.camera.core.impl.A0;
import androidx.camera.core.impl.C0;
import androidx.camera.core.impl.C0158a;
import androidx.camera.core.impl.C0162c;
import androidx.camera.core.impl.C0163c0;
import androidx.camera.core.impl.C0165d0;
import androidx.camera.core.impl.C0168g;
import androidx.camera.core.impl.C0169h;
import androidx.camera.core.impl.C0179s;
import androidx.camera.core.impl.D0;
import androidx.camera.core.impl.H;
import androidx.camera.core.impl.InterfaceC0178q;
import androidx.camera.core.impl.InterfaceC0182v;
import androidx.camera.core.impl.InterfaceC0183w;
import androidx.camera.core.impl.InterfaceC0185y;
import androidx.camera.core.impl.N;
import androidx.camera.core.impl.O;
import androidx.camera.core.impl.P;
import androidx.camera.core.impl.X;
import androidx.camera.core.impl.k0;
import androidx.camera.core.impl.q0;
import androidx.camera.core.l0;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;
import com.google.android.gms.internal.mlkit_vision_barcode.T;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.Executor;

/* loaded from: classes.dex */
public final class g implements InterfaceC0188k {
    public final InterfaceC0185y a;
    public final InterfaceC0185y b;
    public final com.quizlet.data.repository.activitycenter.b c;
    public final K d;
    public final a e;
    public final ArrayList f;
    public final ArrayList g;
    public final androidx.camera.camera2.internal.concurrent.a h;
    public List i;
    public final C0179s j;
    public final Object k;
    public boolean l;
    public H m;
    public l0 n;
    public androidx.camera.core.streamsharing.d o;
    public final k0 p;
    public final k0 q;
    public final Q r;
    public final Q s;

    public g(InterfaceC0185y interfaceC0185y, InterfaceC0185y interfaceC0185y2, k0 k0Var, k0 k0Var2, androidx.camera.camera2.internal.concurrent.a aVar, com.quizlet.data.repository.activitycenter.b bVar, K k) {
        Q q = Q.a;
        this.f = new ArrayList();
        this.g = new ArrayList();
        this.i = Collections.EMPTY_LIST;
        this.k = new Object();
        this.l = true;
        this.m = null;
        this.a = interfaceC0185y;
        this.b = interfaceC0185y2;
        this.r = q;
        this.s = q;
        this.h = aVar;
        this.c = bVar;
        this.d = k;
        C0179s c0179s = k0Var.c;
        this.j = c0179s;
        c0179s.y();
        this.p = k0Var;
        this.q = k0Var2;
        this.e = t(k0Var, k0Var2);
    }

    public static ArrayList A(ArrayList arrayList, List list) {
        ArrayList arrayList2 = new ArrayList(list);
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            ((l0) it2.next()).getClass();
            Iterator it3 = list.iterator();
            if (it3.hasNext()) {
                throw android.support.v4.media.session.a.d(it3);
            }
        }
        return arrayList2;
    }

    public static Matrix o(Rect rect, Size size) {
        AbstractC3242q6.c("Cannot compute viewport crop rects zero sized sensor rect.", rect.width() > 0 && rect.height() > 0);
        RectF rectF = new RectF(rect);
        Matrix matrix = new Matrix();
        matrix.setRectToRect(new RectF(DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, size.getWidth(), size.getHeight()), rectF, Matrix.ScaleToFit.CENTER);
        matrix.invert(matrix);
        return matrix;
    }

    public static L q() {
        Object objE;
        Object objE2;
        Object objE3;
        com.google.android.gms.auth.api.signin.internal.h hVar = new com.google.android.gms.auth.api.signin.internal.h(6);
        C0162c c0162c = k.z0;
        X x = (X) hVar.b;
        x.m(c0162c, "ImageCapture-Extra");
        C0162c c0162c2 = N.d;
        x.getClass();
        Object objE4 = null;
        try {
            objE = x.e(c0162c2);
        } catch (IllegalArgumentException unused) {
            objE = null;
        }
        Integer num = (Integer) objE;
        if (num != null) {
            x.m(O.b0, num);
        } else {
            I i = L.x;
            try {
                objE2 = x.e(N.e);
            } catch (IllegalArgumentException unused2) {
                objE2 = null;
            }
            if (Objects.equals(objE2, 1)) {
                x.m(O.b0, 4101);
                x.m(O.c0, C0196t.c);
            } else {
                x.m(O.b0, 256);
            }
        }
        N n = new N(C0163c0.a(x));
        P.u(n);
        L l = new L(n);
        try {
            objE3 = x.e(P.h0);
        } catch (IllegalArgumentException unused3) {
            objE3 = null;
        }
        Size size = (Size) objE3;
        if (size != null) {
            new Rational(size.getWidth(), size.getHeight());
        }
        C0162c c0162c3 = h.y0;
        Object objD = T.d();
        try {
            objD = x.e(c0162c3);
        } catch (IllegalArgumentException unused4) {
        }
        AbstractC3242q6.g((Executor) objD, "The IO executor can't be null");
        C0162c c0162c4 = N.c;
        if (x.a.containsKey(c0162c4)) {
            Integer num2 = (Integer) x.e(c0162c4);
            if (num2 == null || !(num2.intValue() == 0 || num2.intValue() == 1 || num2.intValue() == 3 || num2.intValue() == 2)) {
                throw new IllegalArgumentException("The flash mode is not allowed to set: " + num2);
            }
            if (num2.intValue() == 3) {
                try {
                    objE4 = x.e(N.i);
                } catch (IllegalArgumentException unused5) {
                }
                if (objE4 == null) {
                    throw new IllegalArgumentException("The flash mode is not allowed to set to FLASH_MODE_SCREEN without setting ScreenFlash");
                }
            }
        }
        return l;
    }

    public static a t(k0 k0Var, k0 k0Var2) {
        StringBuilder sb = new StringBuilder();
        sb.append(k0Var.a.c());
        sb.append(k0Var2 == null ? "" : k0Var2.a.c());
        return new a(sb.toString(), k0Var.c.a);
    }

    public static HashMap u(ArrayList arrayList, D0 d0, K k) {
        A0 a0E;
        HashMap map = new HashMap();
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            l0 l0Var = (l0) it2.next();
            if (l0Var instanceof androidx.camera.core.streamsharing.d) {
                androidx.camera.core.streamsharing.d dVar = (androidx.camera.core.streamsharing.d) l0Var;
                C0165d0 c0165d0 = new C0165d0(C0163c0.a((X) new com.google.android.gms.internal.instantapps.a(6).b));
                P.u(c0165d0);
                androidx.camera.core.X x = new androidx.camera.core.X(c0165d0);
                x.p = androidx.camera.core.X.w;
                A0 a0E2 = x.e(false, d0);
                if (a0E2 == null) {
                    a0E = null;
                } else {
                    X xK = X.k(a0E2);
                    xK.a.remove(k.A0);
                    a0E = ((androidx.appcompat.app.L) dVar.j(xK)).s();
                }
            } else {
                a0E = l0Var.e(false, d0);
            }
            A0 a0E3 = l0Var.e(true, k);
            f fVar = new f();
            fVar.a = a0E;
            fVar.b = a0E3;
            map.put(l0Var, fVar);
        }
        return map;
    }

    public static boolean y(C0168g c0168g, q0 q0Var) {
        C0163c0 c0163c0 = q0Var.g.b;
        androidx.camera.camera2.impl.b bVar = c0168g.d;
        if (bVar.f().size() != q0Var.g.b.f().size()) {
            return true;
        }
        for (C0162c c0162c : bVar.f()) {
            if (!c0163c0.a.containsKey(c0162c) || !Objects.equals(c0163c0.e(c0162c), bVar.e(c0162c))) {
                return true;
            }
        }
        return false;
    }

    public final void B(LinkedHashSet linkedHashSet, boolean z) {
        int i;
        int i2;
        HashMap map;
        C0168g c0168g;
        androidx.camera.camera2.impl.b bVar;
        boolean z2;
        synchronized (this.k) {
            x();
            synchronized (this.k) {
                try {
                    i = 0;
                    if (!this.i.isEmpty()) {
                        Iterator it2 = linkedHashSet.iterator();
                        while (true) {
                            if (!it2.hasNext()) {
                                z2 = false;
                                break;
                            }
                            l0 l0Var = (l0) it2.next();
                            if (l0Var instanceof L) {
                                A0 a0 = l0Var.f;
                                C0162c c0162c = N.e;
                                if (a0.c(c0162c)) {
                                    Integer num = (Integer) a0.e(c0162c);
                                    num.getClass();
                                    if (num.intValue() == 1) {
                                        z2 = true;
                                        break;
                                    }
                                } else {
                                    continue;
                                }
                            }
                        }
                        if (z2) {
                            throw new IllegalArgumentException("Ultra HDR image capture does not support for use with CameraEffect.");
                        }
                    }
                } finally {
                }
            }
            if (!z) {
                x();
            }
            androidx.camera.core.streamsharing.d dVarR = r(linkedHashSet, z);
            l0 l0VarE = e(linkedHashSet, dVarR);
            ArrayList arrayList = new ArrayList(linkedHashSet);
            if (l0VarE != null) {
                arrayList.add(l0VarE);
            }
            if (dVarR != null) {
                arrayList.add(dVarR);
                arrayList.removeAll(dVarR.p.a);
            }
            ArrayList arrayList2 = new ArrayList(arrayList);
            arrayList2.removeAll(this.g);
            ArrayList arrayList3 = new ArrayList(arrayList);
            arrayList3.retainAll(this.g);
            ArrayList arrayList4 = new ArrayList(this.g);
            arrayList4.removeAll(arrayList);
            HashMap mapU = u(arrayList2, (D0) this.j.j(InterfaceC0178q.R, D0.a), this.d);
            Map mapP = Collections.EMPTY_MAP;
            try {
                synchronized (this.k) {
                    try {
                        i2 = this.h.b == 2 ? 1 : 0;
                    } finally {
                    }
                }
                HashMap mapP2 = p(i2, this.a.n(), arrayList2, arrayList3, mapU);
                if (this.b != null) {
                    synchronized (this.k) {
                        try {
                            if (this.h.b == 2) {
                                i = 1;
                            }
                        } finally {
                        }
                    }
                    InterfaceC0185y interfaceC0185y = this.b;
                    Objects.requireNonNull(interfaceC0185y);
                    int i3 = i;
                    map = mapP2;
                    mapP = p(i3, interfaceC0185y.n(), arrayList2, arrayList3, mapU);
                } else {
                    map = mapP2;
                }
                C(map, arrayList);
                ArrayList arrayListA = A(arrayList, this.i);
                ArrayList arrayList5 = new ArrayList(linkedHashSet);
                arrayList5.removeAll(arrayList);
                ArrayList arrayListA2 = A(arrayList5, arrayListA);
                if (arrayListA2.size() > 0) {
                    AbstractC3053s1.h("CameraUseCaseAdapter", "Unused effects: " + arrayListA2);
                }
                Iterator it3 = arrayList4.iterator();
                while (it3.hasNext()) {
                    ((l0) it3.next()).z(this.a);
                }
                this.a.j(arrayList4);
                if (this.b != null) {
                    Iterator it4 = arrayList4.iterator();
                    while (it4.hasNext()) {
                        l0 l0Var2 = (l0) it4.next();
                        InterfaceC0185y interfaceC0185y2 = this.b;
                        Objects.requireNonNull(interfaceC0185y2);
                        l0Var2.z(interfaceC0185y2);
                    }
                    InterfaceC0185y interfaceC0185y3 = this.b;
                    Objects.requireNonNull(interfaceC0185y3);
                    interfaceC0185y3.j(arrayList4);
                }
                if (arrayList4.isEmpty()) {
                    Iterator it5 = arrayList3.iterator();
                    while (it5.hasNext()) {
                        l0 l0Var3 = (l0) it5.next();
                        if (map.containsKey(l0Var3) && (bVar = (c0168g = (C0168g) map.get(l0Var3)).d) != null && y(c0168g, l0Var3.m)) {
                            l0Var3.g = l0Var3.u(bVar);
                            if (this.l) {
                                this.a.e(l0Var3);
                                InterfaceC0185y interfaceC0185y4 = this.b;
                                if (interfaceC0185y4 != null) {
                                    interfaceC0185y4.e(l0Var3);
                                }
                            }
                        }
                    }
                }
                Iterator it6 = arrayList2.iterator();
                while (it6.hasNext()) {
                    l0 l0Var4 = (l0) it6.next();
                    f fVar = (f) mapU.get(l0Var4);
                    Objects.requireNonNull(fVar);
                    InterfaceC0185y interfaceC0185y5 = this.b;
                    if (interfaceC0185y5 != null) {
                        l0Var4.a(this.a, interfaceC0185y5, fVar.a, fVar.b);
                        C0168g c0168g2 = (C0168g) map.get(l0Var4);
                        c0168g2.getClass();
                        l0Var4.g = l0Var4.v(c0168g2, (C0168g) mapP.get(l0Var4));
                    } else {
                        l0Var4.a(this.a, null, fVar.a, fVar.b);
                        C0168g c0168g3 = (C0168g) map.get(l0Var4);
                        c0168g3.getClass();
                        l0Var4.g = l0Var4.v(c0168g3, null);
                    }
                }
                if (this.l) {
                    this.a.k(arrayList2);
                    InterfaceC0185y interfaceC0185y6 = this.b;
                    if (interfaceC0185y6 != null) {
                        interfaceC0185y6.k(arrayList2);
                    }
                }
                Iterator it7 = arrayList2.iterator();
                while (it7.hasNext()) {
                    ((l0) it7.next()).o();
                }
                this.f.clear();
                this.f.addAll(linkedHashSet);
                this.g.clear();
                this.g.addAll(arrayList);
                this.n = l0VarE;
                this.o = dVarR;
            } catch (IllegalArgumentException e) {
                if (!z) {
                    x();
                    if (this.h.b != 2) {
                        B(linkedHashSet, true);
                        return;
                    }
                }
                throw e;
            }
        }
    }

    public final void C(HashMap map, ArrayList arrayList) {
        synchronized (this.k) {
            try {
                Iterator it2 = arrayList.iterator();
                while (it2.hasNext()) {
                    l0 l0Var = (l0) it2.next();
                    Rect rectB = this.a.g().b();
                    C0168g c0168g = (C0168g) map.get(l0Var);
                    c0168g.getClass();
                    l0Var.x(o(rectB, c0168g.a));
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // androidx.camera.core.InterfaceC0188k
    public final InterfaceC0183w a() {
        return this.p;
    }

    public final void c(List list) {
        synchronized (this.k) {
            try {
                this.a.b(this.j);
                InterfaceC0185y interfaceC0185y = this.b;
                if (interfaceC0185y != null) {
                    interfaceC0185y.b(this.j);
                }
                LinkedHashSet linkedHashSet = new LinkedHashSet(this.f);
                linkedHashSet.addAll(list);
                try {
                    B(linkedHashSet, this.b != null);
                } catch (IllegalArgumentException e) {
                    throw new CameraUseCaseAdapter$CameraException(e);
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public final void d() {
        synchronized (this.k) {
            try {
                if (!this.l) {
                    if (!this.g.isEmpty()) {
                        this.a.b(this.j);
                        InterfaceC0185y interfaceC0185y = this.b;
                        if (interfaceC0185y != null) {
                            interfaceC0185y.b(this.j);
                        }
                    }
                    this.a.k(this.g);
                    InterfaceC0185y interfaceC0185y2 = this.b;
                    if (interfaceC0185y2 != null) {
                        interfaceC0185y2.k(this.g);
                    }
                    synchronized (this.k) {
                        try {
                            if (this.m != null) {
                                this.a.g().a(this.m);
                            }
                        } finally {
                        }
                    }
                    Iterator it2 = this.g.iterator();
                    while (it2.hasNext()) {
                        ((l0) it2.next()).o();
                    }
                    this.l = true;
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:53:0x00cb  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final androidx.camera.core.l0 e(java.util.LinkedHashSet r8, androidx.camera.core.streamsharing.d r9) {
        /*
            Method dump skipped, instructions count: 211
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.camera.core.internal.g.e(java.util.LinkedHashSet, androidx.camera.core.streamsharing.d):androidx.camera.core.l0");
    }

    public final HashMap p(int i, InterfaceC0183w interfaceC0183w, ArrayList arrayList, ArrayList arrayList2, HashMap map) {
        com.quizlet.data.repository.activitycenter.b bVar;
        Rect rectB;
        boolean z;
        ArrayList arrayList3 = new ArrayList();
        String strC = interfaceC0183w.c();
        HashMap map2 = new HashMap();
        HashMap map3 = new HashMap();
        Iterator it2 = arrayList2.iterator();
        while (true) {
            boolean zHasNext = it2.hasNext();
            bVar = this.c;
            if (!zHasNext) {
                break;
            }
            l0 l0Var = (l0) it2.next();
            int iO = l0Var.f.o();
            C0168g c0168g = l0Var.g;
            Size size = c0168g != null ? c0168g.a : null;
            f0 f0Var = (f0) ((HashMap) bVar.b).get(strC);
            C0169h c0169hB = f0Var != null ? C0169h.b(i, iO, size, f0Var.i(iO)) : null;
            int iO2 = l0Var.f.o();
            C0168g c0168g2 = l0Var.g;
            Size size2 = c0168g2 != null ? c0168g2.a : null;
            c0168g2.getClass();
            C0158a c0158a = new C0158a(c0169hB, iO2, size2, c0168g2.b, androidx.camera.core.streamsharing.d.F(l0Var), l0Var.g.d, (Range) l0Var.f.j(A0.s0, null));
            arrayList3.add(c0158a);
            map3.put(c0158a, l0Var);
            map2.put(l0Var, l0Var.g);
        }
        if (!arrayList.isEmpty()) {
            HashMap map4 = new HashMap();
            HashMap map5 = new HashMap();
            try {
                rectB = this.a.g().b();
            } catch (NullPointerException unused) {
                rectB = null;
            }
            com.quizlet.data.repository.set.f fVar = new com.quizlet.data.repository.set.f(interfaceC0183w, rectB != null ? androidx.camera.core.impl.utils.f.d(rectB) : null);
            Iterator it3 = arrayList.iterator();
            boolean z2 = false;
            while (it3.hasNext()) {
                l0 l0Var2 = (l0) it3.next();
                f fVar2 = (f) map.get(l0Var2);
                A0 a0L = l0Var2.l(interfaceC0183w, fVar2.a, fVar2.b);
                map4.put(a0L, l0Var2);
                map5.put(a0L, fVar.l(a0L));
                A0 a0 = l0Var2.f;
                if (a0 instanceof C0165d0) {
                    z2 = ((C0165d0) a0).A() == 2;
                }
            }
            Iterator it4 = arrayList.iterator();
            while (true) {
                if (!it4.hasNext()) {
                    z = false;
                    break;
                }
                l0 l0Var3 = (l0) it4.next();
                if (l0Var3 != null) {
                    if (l0Var3.f.c(A0.v0)) {
                        if (l0Var3.f.x() == C0.d) {
                            z = true;
                            break;
                        }
                    } else {
                        Log.e("CameraUseCaseAdapter", l0Var3 + " UseCase does not have capture type.");
                    }
                }
            }
            bVar.getClass();
            AbstractC3242q6.c("No new use cases to be bound.", !map5.isEmpty());
            f0 f0Var2 = (f0) ((HashMap) bVar.b).get(strC);
            if (f0Var2 == null) {
                throw new IllegalArgumentException(AbstractC0147y.d("No such camera id in supported combination list: ", strC));
            }
            Pair pairG = f0Var2.g(i, arrayList3, map5, z2, z);
            for (Map.Entry entry : map4.entrySet()) {
                map2.put((l0) entry.getValue(), (C0168g) ((Map) pairG.first).get(entry.getKey()));
            }
            for (Map.Entry entry2 : ((Map) pairG.second).entrySet()) {
                if (map3.containsKey(entry2.getKey())) {
                    map2.put((l0) map3.get(entry2.getKey()), (C0168g) entry2.getValue());
                }
            }
        }
        return map2;
    }

    public final androidx.camera.core.streamsharing.d r(LinkedHashSet linkedHashSet, boolean z) {
        boolean z2;
        synchronized (this.k) {
            try {
                HashSet hashSetV = v(linkedHashSet, z);
                if (hashSetV.size() < 2) {
                    x();
                    return null;
                }
                androidx.camera.core.streamsharing.d dVar = this.o;
                if (dVar != null && dVar.p.a.equals(hashSetV)) {
                    androidx.camera.core.streamsharing.d dVar2 = this.o;
                    Objects.requireNonNull(dVar2);
                    return dVar2;
                }
                int[] iArr = {1, 2, 4};
                HashSet hashSet = new HashSet();
                Iterator it2 = hashSetV.iterator();
                while (it2.hasNext()) {
                    l0 l0Var = (l0) it2.next();
                    for (int i = 0; i < 3; i++) {
                        int i2 = iArr[i];
                        Iterator it3 = l0Var.i().iterator();
                        while (true) {
                            if (!it3.hasNext()) {
                                z2 = false;
                                break;
                            }
                            int iIntValue = ((Integer) it3.next()).intValue();
                            if ((i2 & iIntValue) == iIntValue) {
                                z2 = true;
                                break;
                            }
                        }
                        if (z2) {
                            if (hashSet.contains(Integer.valueOf(i2))) {
                                return null;
                            }
                            hashSet.add(Integer.valueOf(i2));
                        }
                    }
                }
                return new androidx.camera.core.streamsharing.d(this.a, this.b, this.r, this.s, hashSetV, this.d);
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public final void s() {
        synchronized (this.k) {
            try {
                if (this.l) {
                    this.a.j(new ArrayList(this.g));
                    InterfaceC0185y interfaceC0185y = this.b;
                    if (interfaceC0185y != null) {
                        interfaceC0185y.j(new ArrayList(this.g));
                    }
                    synchronized (this.k) {
                        InterfaceC0182v interfaceC0182vG = this.a.g();
                        this.m = interfaceC0182vG.e();
                        interfaceC0182vG.g();
                    }
                    this.l = false;
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public final HashSet v(LinkedHashSet linkedHashSet, boolean z) {
        int i;
        HashSet hashSet = new HashSet();
        synchronized (this.k) {
            Iterator it2 = this.i.iterator();
            if (it2.hasNext()) {
                if (it2.next() == null) {
                    throw null;
                }
                throw new ClassCastException();
            }
            i = z ? 3 : 0;
        }
        Iterator it3 = linkedHashSet.iterator();
        while (it3.hasNext()) {
            l0 l0Var = (l0) it3.next();
            AbstractC3242q6.c("Only support one level of sharing for now.", !(l0Var instanceof androidx.camera.core.streamsharing.d));
            Iterator it4 = l0Var.i().iterator();
            while (true) {
                if (it4.hasNext()) {
                    int iIntValue = ((Integer) it4.next()).intValue();
                    if ((i & iIntValue) == iIntValue) {
                        hashSet.add(l0Var);
                        break;
                    }
                }
            }
        }
        return hashSet;
    }

    public final List w() {
        ArrayList arrayList;
        synchronized (this.k) {
            arrayList = new ArrayList(this.f);
        }
        return arrayList;
    }

    public final void x() {
        synchronized (this.k) {
            this.j.y();
        }
    }

    public final void z(ArrayList arrayList) {
        synchronized (this.k) {
            LinkedHashSet linkedHashSet = new LinkedHashSet(this.f);
            linkedHashSet.removeAll(arrayList);
            B(linkedHashSet, this.b != null);
        }
    }
}

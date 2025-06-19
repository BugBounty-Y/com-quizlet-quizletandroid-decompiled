package androidx.camera.core;

import android.util.ArrayMap;
import android.view.Surface;
import androidx.camera.camera2.internal.C0143u;
import androidx.camera.core.impl.AbstractC0171j;
import androidx.camera.core.impl.C0162c;
import androidx.camera.core.impl.C0163c0;
import androidx.camera.core.impl.InterfaceC0177p;
import androidx.camera.core.impl.v0;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.Executor;

/* loaded from: classes.dex */
public final class a0 implements androidx.camera.core.impl.S {
    public int a;
    public boolean b;
    public final Object c;
    public Object d;
    public final Object e;
    public Object f;
    public Object g;

    public a0(coil3.request.g gVar, List list, int i, coil3.request.g gVar2, coil3.size.h hVar, coil3.f fVar, boolean z) {
        this.c = gVar;
        this.d = list;
        this.a = i;
        this.e = gVar2;
        this.f = hVar;
        this.g = fVar;
        this.b = z;
    }

    @Override // androidx.camera.core.impl.S
    public int C() {
        int iC;
        synchronized (this.c) {
            iC = ((androidx.camera.core.impl.S) this.d).C();
        }
        return iC;
    }

    @Override // androidx.camera.core.impl.S
    public O F() {
        G g;
        synchronized (this.c) {
            O oF = ((androidx.camera.core.impl.S) this.d).F();
            if (oF != null) {
                this.a++;
                g = new G(oF);
                g.a((F) this.g);
            } else {
                g = null;
            }
        }
        return g;
    }

    @Override // androidx.camera.core.impl.S
    public void G(androidx.camera.core.impl.Q q, Executor executor) {
        synchronized (this.c) {
            ((androidx.camera.core.impl.S) this.d).G(new C0143u(4, this, q), executor);
        }
    }

    public void a(Collection collection) {
        Iterator it2 = collection.iterator();
        while (it2.hasNext()) {
            c((AbstractC0171j) it2.next());
        }
    }

    @Override // androidx.camera.core.impl.S
    public int b() {
        int iB;
        synchronized (this.c) {
            iB = ((androidx.camera.core.impl.S) this.d).b();
        }
        return iB;
    }

    public void c(AbstractC0171j abstractC0171j) {
        ArrayList arrayList = (ArrayList) this.e;
        if (arrayList.contains(abstractC0171j)) {
            return;
        }
        arrayList.add(abstractC0171j);
    }

    @Override // androidx.camera.core.impl.S
    public void close() {
        synchronized (this.c) {
            try {
                Surface surface = (Surface) this.e;
                if (surface != null) {
                    surface.release();
                }
                ((androidx.camera.core.impl.S) this.d).close();
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public void d(androidx.camera.core.impl.H h) {
        for (C0162c c0162c : h.f()) {
            androidx.camera.core.impl.X x = (androidx.camera.core.impl.X) this.d;
            x.getClass();
            try {
                x.e(c0162c);
            } catch (IllegalArgumentException unused) {
            }
            ((androidx.camera.core.impl.X) this.d).l(c0162c, h.i(c0162c), h.e(c0162c));
        }
    }

    public androidx.camera.core.impl.F e() {
        ArrayList arrayList = new ArrayList((HashSet) this.c);
        C0163c0 c0163c0A = C0163c0.a((androidx.camera.core.impl.X) this.d);
        int i = this.a;
        ArrayList arrayList2 = new ArrayList((ArrayList) this.e);
        boolean z = this.b;
        v0 v0Var = v0.b;
        ArrayMap arrayMap = new ArrayMap();
        androidx.camera.core.impl.Z z2 = (androidx.camera.core.impl.Z) this.f;
        for (String str : z2.a.keySet()) {
            arrayMap.put(str, z2.a.get(str));
        }
        return new androidx.camera.core.impl.F(arrayList, c0163c0A, i, arrayList2, z, new v0(arrayMap), (InterfaceC0177p) this.g);
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object f(kotlin.coroutines.jvm.internal.c r13) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 264
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.camera.core.a0.f(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public void g() {
        synchronized (this.c) {
            try {
                this.b = true;
                ((androidx.camera.core.impl.S) this.d).p();
                if (this.a == 0) {
                    close();
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // androidx.camera.core.impl.S
    public int getWidth() {
        int width;
        synchronized (this.c) {
            width = ((androidx.camera.core.impl.S) this.d).getWidth();
        }
        return width;
    }

    @Override // androidx.camera.core.impl.S
    public O l() {
        G g;
        synchronized (this.c) {
            O oL = ((androidx.camera.core.impl.S) this.d).l();
            if (oL != null) {
                this.a++;
                g = new G(oL);
                g.a((F) this.g);
            } else {
                g = null;
            }
        }
        return g;
    }

    @Override // androidx.camera.core.impl.S
    public int m() {
        int iM;
        synchronized (this.c) {
            iM = ((androidx.camera.core.impl.S) this.d).m();
        }
        return iM;
    }

    @Override // androidx.camera.core.impl.S
    public void p() {
        synchronized (this.c) {
            ((androidx.camera.core.impl.S) this.d).p();
        }
    }

    @Override // androidx.camera.core.impl.S
    public Surface w() {
        Surface surfaceW;
        synchronized (this.c) {
            surfaceW = ((androidx.camera.core.impl.S) this.d).w();
        }
        return surfaceW;
    }

    public a0(androidx.camera.core.impl.S s) {
        this.c = new Object();
        this.a = 0;
        this.b = false;
        this.g = new F(this, 1);
        this.d = s;
        this.e = s.w();
    }

    public a0() {
        this.c = new HashSet();
        this.d = androidx.camera.core.impl.X.b();
        this.a = -1;
        this.e = new ArrayList();
        this.b = false;
        this.f = androidx.camera.core.impl.Z.a();
    }

    public a0(androidx.camera.core.impl.F f) {
        HashSet hashSet = new HashSet();
        this.c = hashSet;
        this.d = androidx.camera.core.impl.X.b();
        this.a = -1;
        ArrayList arrayList = new ArrayList();
        this.e = arrayList;
        this.b = false;
        this.f = androidx.camera.core.impl.Z.a();
        hashSet.addAll(f.a);
        this.d = androidx.camera.core.impl.X.k(f.b);
        this.a = f.c;
        arrayList.addAll(f.d);
        this.b = f.e;
        ArrayMap arrayMap = new ArrayMap();
        v0 v0Var = f.f;
        for (String str : v0Var.a.keySet()) {
            arrayMap.put(str, v0Var.a.get(str));
        }
        this.f = new androidx.camera.core.impl.Z(arrayMap);
    }
}

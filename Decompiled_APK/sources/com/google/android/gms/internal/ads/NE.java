package com.google.android.gms.internal.ads;

import android.os.Looper;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.concurrent.CopyOnWriteArrayList;

/* loaded from: classes2.dex */
public abstract class NE {
    public final ArrayList a = new ArrayList(1);
    public final HashSet b = new HashSet(1);
    public final C2866yE c = new C2866yE(new CopyOnWriteArrayList(), null);
    public final C2866yE d = new C2866yE(new CopyOnWriteArrayList(), null);
    public Looper e;
    public A9 f;
    public C1917cE g;

    public abstract void a(InterfaceC2005eF interfaceC2005eF);

    public abstract InterfaceC2005eF b(C2093gF c2093gF, C1963dG c1963dG, long j);

    public abstract C2640t3 c();

    public void d() {
    }

    public final void e(InterfaceC2137hF interfaceC2137hF) {
        HashSet hashSet = this.b;
        boolean zIsEmpty = hashSet.isEmpty();
        hashSet.remove(interfaceC2137hF);
        if (zIsEmpty || !hashSet.isEmpty()) {
            return;
        }
        f();
    }

    public void f() {
    }

    public final void g(InterfaceC2137hF interfaceC2137hF) {
        this.e.getClass();
        HashSet hashSet = this.b;
        boolean zIsEmpty = hashSet.isEmpty();
        hashSet.add(interfaceC2137hF);
        if (zIsEmpty) {
            h();
        }
    }

    public void h() {
    }

    public final void i(InterfaceC2137hF interfaceC2137hF, C2050fG c2050fG, C1917cE c1917cE) {
        Looper looperMyLooper = Looper.myLooper();
        Looper looper = this.e;
        boolean z = true;
        if (looper != null && looper != looperMyLooper) {
            z = false;
        }
        AbstractC1795We.B(z);
        this.g = c1917cE;
        A9 a9 = this.f;
        this.a.add(interfaceC2137hF);
        if (this.e == null) {
            this.e = looperMyLooper;
            this.b.add(interfaceC2137hF);
            j(c2050fG);
        } else if (a9 != null) {
            g(interfaceC2137hF);
            interfaceC2137hF.a(this, a9);
        }
    }

    public abstract void j(C2050fG c2050fG);

    public final void k(A9 a9) {
        this.f = a9;
        ArrayList arrayList = this.a;
        int size = arrayList.size();
        for (int i = 0; i < size; i++) {
            ((InterfaceC2137hF) arrayList.get(i)).a(this, a9);
        }
    }

    public final void l(InterfaceC2137hF interfaceC2137hF) {
        ArrayList arrayList = this.a;
        arrayList.remove(interfaceC2137hF);
        if (!arrayList.isEmpty()) {
            e(interfaceC2137hF);
            return;
        }
        this.e = null;
        this.f = null;
        this.g = null;
        this.b.clear();
        m();
    }

    public abstract void m();

    public final void n(InterfaceC2909zE interfaceC2909zE) {
        CopyOnWriteArrayList copyOnWriteArrayList = this.d.b;
        Iterator it2 = copyOnWriteArrayList.iterator();
        while (it2.hasNext()) {
            C2823xE c2823xE = (C2823xE) it2.next();
            if (c2823xE.a == interfaceC2909zE) {
                copyOnWriteArrayList.remove(c2823xE);
            }
        }
    }

    public final void o(InterfaceC2266kF interfaceC2266kF) {
        CopyOnWriteArrayList copyOnWriteArrayList = this.c.b;
        Iterator it2 = copyOnWriteArrayList.iterator();
        while (it2.hasNext()) {
            C2223jF c2223jF = (C2223jF) it2.next();
            if (c2223jF.b == interfaceC2266kF) {
                copyOnWriteArrayList.remove(c2223jF);
            }
        }
    }

    public abstract void p(C2640t3 c2640t3);

    public void q() {
    }

    public abstract void r();
}

package androidx.transition;

import android.animation.Animator;
import android.animation.TimeInterpolator;
import android.util.SparseArray;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ListView;
import androidx.appcompat.widget.C0076c;
import androidx.collection.C0208f;
import androidx.collection.C0219q;
import androidx.core.view.C1041c0;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.WeakHashMap;

/* loaded from: classes.dex */
public abstract class y implements Cloneable {
    public static final Animator[] B = new Animator[0];
    public static final int[] C = {2, 1, 3, 4};
    public static final C1411n D = new C1411n();
    public static final ThreadLocal E = new ThreadLocal();
    public long A;
    public ArrayList k;
    public ArrayList l;
    public InterfaceC1419w[] m;
    public C1411n v;
    public C1405h w;
    public long y;
    public C1418v z;
    public final String a = getClass().getName();
    public long b = -1;
    public long c = -1;
    public TimeInterpolator d = null;
    public final ArrayList e = new ArrayList();
    public final ArrayList f = new ArrayList();
    public androidx.work.impl.model.i g = new androidx.work.impl.model.i();
    public androidx.work.impl.model.i h = new androidx.work.impl.model.i();
    public F i = null;
    public final int[] j = C;
    public final ArrayList n = new ArrayList();
    public Animator[] o = B;
    public int p = 0;
    public boolean q = false;
    public boolean r = false;
    public y s = null;
    public ArrayList t = null;
    public ArrayList u = new ArrayList();
    public C1411n x = D;

    public static void d(androidx.work.impl.model.i iVar, View view, I i) {
        ((C0208f) iVar.b).put(view, i);
        int id = view.getId();
        if (id >= 0) {
            SparseArray sparseArray = (SparseArray) iVar.c;
            if (sparseArray.indexOfKey(id) >= 0) {
                sparseArray.put(id, null);
            } else {
                sparseArray.put(id, view);
            }
        }
        WeakHashMap weakHashMap = androidx.core.view.V.a;
        String strF = androidx.core.view.L.f(view);
        if (strF != null) {
            C0208f c0208f = (C0208f) iVar.e;
            if (c0208f.containsKey(strF)) {
                c0208f.put(strF, null);
            } else {
                c0208f.put(strF, view);
            }
        }
        if (view.getParent() instanceof ListView) {
            ListView listView = (ListView) view.getParent();
            if (listView.getAdapter().hasStableIds()) {
                long itemIdAtPosition = listView.getItemIdAtPosition(listView.getPositionForView(view));
                C0219q c0219q = (C0219q) iVar.d;
                if (c0219q.e(itemIdAtPosition) < 0) {
                    view.setHasTransientState(true);
                    c0219q.g(itemIdAtPosition, view);
                    return;
                }
                View view2 = (View) c0219q.c(itemIdAtPosition);
                if (view2 != null) {
                    view2.setHasTransientState(false);
                    c0219q.g(itemIdAtPosition, null);
                }
            }
        }
    }

    public static C0208f r() {
        ThreadLocal threadLocal = E;
        C0208f c0208f = (C0208f) threadLocal.get();
        if (c0208f != null) {
            return c0208f;
        }
        C0208f c0208f2 = new C0208f(0);
        threadLocal.set(c0208f2);
        return c0208f2;
    }

    public static boolean y(I i, I i2, String str) {
        Object obj = i.a.get(str);
        Object obj2 = i2.a.get(str);
        if (obj == null && obj2 == null) {
            return false;
        }
        if (obj == null || obj2 == null) {
            return true;
        }
        return !obj.equals(obj2);
    }

    public void A(ViewGroup viewGroup) {
        if (this.r) {
            return;
        }
        ArrayList arrayList = this.n;
        int size = arrayList.size();
        Animator[] animatorArr = (Animator[]) arrayList.toArray(this.o);
        this.o = B;
        for (int i = size - 1; i >= 0; i--) {
            Animator animator = animatorArr[i];
            animatorArr[i] = null;
            animator.pause();
        }
        this.o = animatorArr;
        z(this, x.J0, false);
        this.q = true;
    }

    public void B() {
        C0208f c0208fR = r();
        this.y = 0L;
        for (int i = 0; i < this.u.size(); i++) {
            Animator animator = (Animator) this.u.get(i);
            C1415s c1415s = (C1415s) c0208fR.get(animator);
            if (animator != null && c1415s != null) {
                long j = this.c;
                Animator animator2 = c1415s.f;
                if (j >= 0) {
                    animator2.setDuration(j);
                }
                long j2 = this.b;
                if (j2 >= 0) {
                    animator2.setStartDelay(animator2.getStartDelay() + j2);
                }
                TimeInterpolator timeInterpolator = this.d;
                if (timeInterpolator != null) {
                    animator2.setInterpolator(timeInterpolator);
                }
                this.n.add(animator);
                this.y = Math.max(this.y, AbstractC1416t.a(animator));
            }
        }
        this.u.clear();
    }

    public y D(InterfaceC1419w interfaceC1419w) {
        y yVar;
        ArrayList arrayList = this.t;
        if (arrayList != null) {
            if (!arrayList.remove(interfaceC1419w) && (yVar = this.s) != null) {
                yVar.D(interfaceC1419w);
            }
            if (this.t.size() == 0) {
                this.t = null;
            }
        }
        return this;
    }

    public void E(View view) {
        this.f.remove(view);
    }

    public void F(View view) {
        if (this.q) {
            if (!this.r) {
                ArrayList arrayList = this.n;
                int size = arrayList.size();
                Animator[] animatorArr = (Animator[]) arrayList.toArray(this.o);
                this.o = B;
                for (int i = size - 1; i >= 0; i--) {
                    Animator animator = animatorArr[i];
                    animatorArr[i] = null;
                    animator.resume();
                }
                this.o = animatorArr;
                z(this, x.K0, false);
            }
            this.q = false;
        }
    }

    public void G() {
        O();
        C0208f c0208fR = r();
        Iterator it2 = this.u.iterator();
        while (it2.hasNext()) {
            Animator animator = (Animator) it2.next();
            if (c0208fR.containsKey(animator)) {
                O();
                if (animator != null) {
                    animator.addListener(new C1041c0(this, c0208fR));
                    long j = this.c;
                    if (j >= 0) {
                        animator.setDuration(j);
                    }
                    long j2 = this.b;
                    if (j2 >= 0) {
                        animator.setStartDelay(animator.getStartDelay() + j2);
                    }
                    TimeInterpolator timeInterpolator = this.d;
                    if (timeInterpolator != null) {
                        animator.setInterpolator(timeInterpolator);
                    }
                    animator.addListener(new C0076c(this, 1));
                    animator.start();
                }
            }
        }
        this.u.clear();
        o();
    }

    public void H(long j, long j2) {
        long j3 = this.y;
        boolean z = j < j2;
        if ((j2 < 0 && j >= 0) || (j2 > j3 && j <= j3)) {
            this.r = false;
            z(this, x.G0, z);
        }
        ArrayList arrayList = this.n;
        int size = arrayList.size();
        Animator[] animatorArr = (Animator[]) arrayList.toArray(this.o);
        this.o = B;
        for (int i = 0; i < size; i++) {
            Animator animator = animatorArr[i];
            animatorArr[i] = null;
            AbstractC1416t.b(animator, Math.min(Math.max(0L, j), AbstractC1416t.a(animator)));
        }
        this.o = animatorArr;
        if ((j <= j3 || j2 > j3) && (j >= 0 || j2 < 0)) {
            return;
        }
        if (j > j3) {
            this.r = true;
        }
        z(this, x.H0, z);
    }

    public void I(long j) {
        this.c = j;
    }

    public void J(C1405h c1405h) {
        this.w = c1405h;
    }

    public void K(TimeInterpolator timeInterpolator) {
        this.d = timeInterpolator;
    }

    public void L(C1411n c1411n) {
        if (c1411n == null) {
            this.x = D;
        } else {
            this.x = c1411n;
        }
    }

    public void M(C1411n c1411n) {
        this.v = c1411n;
    }

    public void N(long j) {
        this.b = j;
    }

    public final void O() {
        if (this.p == 0) {
            z(this, x.G0, false);
            this.r = false;
        }
        this.p++;
    }

    public String P(String str) {
        StringBuilder sb = new StringBuilder(str);
        sb.append(getClass().getSimpleName());
        sb.append("@");
        sb.append(Integer.toHexString(hashCode()));
        sb.append(": ");
        if (this.c != -1) {
            sb.append("dur(");
            sb.append(this.c);
            sb.append(") ");
        }
        if (this.b != -1) {
            sb.append("dly(");
            sb.append(this.b);
            sb.append(") ");
        }
        if (this.d != null) {
            sb.append("interp(");
            sb.append(this.d);
            sb.append(") ");
        }
        ArrayList arrayList = this.e;
        int size = arrayList.size();
        ArrayList arrayList2 = this.f;
        if (size > 0 || arrayList2.size() > 0) {
            sb.append("tgts(");
            if (arrayList.size() > 0) {
                for (int i = 0; i < arrayList.size(); i++) {
                    if (i > 0) {
                        sb.append(", ");
                    }
                    sb.append(arrayList.get(i));
                }
            }
            if (arrayList2.size() > 0) {
                for (int i2 = 0; i2 < arrayList2.size(); i2++) {
                    if (i2 > 0) {
                        sb.append(", ");
                    }
                    sb.append(arrayList2.get(i2));
                }
            }
            sb.append(")");
        }
        return sb.toString();
    }

    public void b(InterfaceC1419w interfaceC1419w) {
        if (this.t == null) {
            this.t = new ArrayList();
        }
        this.t.add(interfaceC1419w);
    }

    public void c(View view) {
        this.f.add(view);
    }

    public void cancel() {
        ArrayList arrayList = this.n;
        int size = arrayList.size();
        Animator[] animatorArr = (Animator[]) arrayList.toArray(this.o);
        this.o = B;
        for (int i = size - 1; i >= 0; i--) {
            Animator animator = animatorArr[i];
            animatorArr[i] = null;
            animator.cancel();
        }
        this.o = animatorArr;
        z(this, x.I0, false);
    }

    public abstract void e(I i);

    public final void f(View view, boolean z) {
        if (view == null) {
            return;
        }
        view.getId();
        if (view.getParent() instanceof ViewGroup) {
            I i = new I(view);
            if (z) {
                h(i);
            } else {
                e(i);
            }
            i.c.add(this);
            g(i);
            if (z) {
                d(this.g, view, i);
            } else {
                d(this.h, view, i);
            }
        }
        if (view instanceof ViewGroup) {
            ViewGroup viewGroup = (ViewGroup) view;
            for (int i2 = 0; i2 < viewGroup.getChildCount(); i2++) {
                f(viewGroup.getChildAt(i2), z);
            }
        }
    }

    public void g(I i) {
        if (this.v != null) {
            HashMap map = i.a;
            if (map.isEmpty()) {
                return;
            }
            this.v.getClass();
            String[] strArr = C1411n.a;
            for (int i2 = 0; i2 < 2; i2++) {
                if (!map.containsKey(strArr[i2])) {
                    this.v.getClass();
                    Integer numValueOf = (Integer) map.get("android:visibility:visibility");
                    View view = i.b;
                    if (numValueOf == null) {
                        numValueOf = Integer.valueOf(view.getVisibility());
                    }
                    map.put("android:visibilityPropagation:visibility", numValueOf);
                    int[] iArr = {iRound, 0};
                    view.getLocationOnScreen(iArr);
                    int iRound = Math.round(view.getTranslationX()) + iArr[0];
                    iArr[0] = (view.getWidth() / 2) + iRound;
                    int iRound2 = Math.round(view.getTranslationY()) + iArr[1];
                    iArr[1] = iRound2;
                    iArr[1] = (view.getHeight() / 2) + iRound2;
                    map.put("android:visibilityPropagation:center", iArr);
                    return;
                }
            }
        }
    }

    public abstract void h(I i);

    public final void i(ViewGroup viewGroup, boolean z) {
        k(z);
        ArrayList arrayList = this.e;
        int size = arrayList.size();
        ArrayList arrayList2 = this.f;
        if (size <= 0 && arrayList2.size() <= 0) {
            f(viewGroup, z);
            return;
        }
        for (int i = 0; i < arrayList.size(); i++) {
            View viewFindViewById = viewGroup.findViewById(((Integer) arrayList.get(i)).intValue());
            if (viewFindViewById != null) {
                I i2 = new I(viewFindViewById);
                if (z) {
                    h(i2);
                } else {
                    e(i2);
                }
                i2.c.add(this);
                g(i2);
                if (z) {
                    d(this.g, viewFindViewById, i2);
                } else {
                    d(this.h, viewFindViewById, i2);
                }
            }
        }
        for (int i3 = 0; i3 < arrayList2.size(); i3++) {
            View view = (View) arrayList2.get(i3);
            I i4 = new I(view);
            if (z) {
                h(i4);
            } else {
                e(i4);
            }
            i4.c.add(this);
            g(i4);
            if (z) {
                d(this.g, view, i4);
            } else {
                d(this.h, view, i4);
            }
        }
    }

    public final void k(boolean z) {
        if (z) {
            ((C0208f) this.g.b).clear();
            ((SparseArray) this.g.c).clear();
            ((C0219q) this.g.d).b();
        } else {
            ((C0208f) this.h.b).clear();
            ((SparseArray) this.h.c).clear();
            ((C0219q) this.h.d).b();
        }
    }

    @Override // 
    /* renamed from: l, reason: merged with bridge method [inline-methods] */
    public y clone() {
        try {
            y yVar = (y) super.clone();
            yVar.u = new ArrayList();
            yVar.g = new androidx.work.impl.model.i();
            yVar.h = new androidx.work.impl.model.i();
            yVar.k = null;
            yVar.l = null;
            yVar.z = null;
            yVar.s = this;
            yVar.t = null;
            return yVar;
        } catch (CloneNotSupportedException e) {
            throw new RuntimeException(e);
        }
    }

    public Animator m(ViewGroup viewGroup, I i, I i2) {
        return null;
    }

    /* JADX WARN: Removed duplicated region for block: B:100:0x0195  */
    /* JADX WARN: Removed duplicated region for block: B:103:0x01ae  */
    /* JADX WARN: Removed duplicated region for block: B:121:0x01f2 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:55:0x00f5  */
    /* JADX WARN: Removed duplicated region for block: B:89:0x0150  */
    /* JADX WARN: Removed duplicated region for block: B:99:0x018d  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void n(android.view.ViewGroup r25, androidx.work.impl.model.i r26, androidx.work.impl.model.i r27, java.util.ArrayList r28, java.util.ArrayList r29) {
        /*
            Method dump skipped, instructions count: 568
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.transition.y.n(android.view.ViewGroup, androidx.work.impl.model.i, androidx.work.impl.model.i, java.util.ArrayList, java.util.ArrayList):void");
    }

    public final void o() {
        int i = this.p - 1;
        this.p = i;
        if (i == 0) {
            z(this, x.H0, false);
            for (int i2 = 0; i2 < ((C0219q) this.g.d).i(); i2++) {
                View view = (View) ((C0219q) this.g.d).k(i2);
                if (view != null) {
                    view.setHasTransientState(false);
                }
            }
            for (int i3 = 0; i3 < ((C0219q) this.h.d).i(); i3++) {
                View view2 = (View) ((C0219q) this.h.d).k(i3);
                if (view2 != null) {
                    view2.setHasTransientState(false);
                }
            }
            this.r = true;
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:21:0x002c, code lost:
    
        if (r2 < 0) goto L27;
     */
    /* JADX WARN: Code restructure failed: missing block: B:22:0x002e, code lost:
    
        if (r6 == false) goto L24;
     */
    /* JADX WARN: Code restructure failed: missing block: B:23:0x0030, code lost:
    
        r5 = r4.l;
     */
    /* JADX WARN: Code restructure failed: missing block: B:24:0x0033, code lost:
    
        r5 = r4.k;
     */
    /* JADX WARN: Code restructure failed: missing block: B:26:0x003b, code lost:
    
        return (androidx.transition.I) r5.get(r2);
     */
    /* JADX WARN: Code restructure failed: missing block: B:27:0x003c, code lost:
    
        return null;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final androidx.transition.I p(android.view.View r5, boolean r6) {
        /*
            r4 = this;
            androidx.transition.F r0 = r4.i
            if (r0 == 0) goto L9
            androidx.transition.I r5 = r0.p(r5, r6)
            return r5
        L9:
            if (r6 == 0) goto Le
            java.util.ArrayList r0 = r4.k
            goto L10
        Le:
            java.util.ArrayList r0 = r4.l
        L10:
            if (r0 != 0) goto L13
            goto L3c
        L13:
            int r1 = r0.size()
            r2 = 0
        L18:
            if (r2 >= r1) goto L2b
            java.lang.Object r3 = r0.get(r2)
            androidx.transition.I r3 = (androidx.transition.I) r3
            if (r3 != 0) goto L23
            goto L3c
        L23:
            android.view.View r3 = r3.b
            if (r3 != r5) goto L28
            goto L2c
        L28:
            int r2 = r2 + 1
            goto L18
        L2b:
            r2 = -1
        L2c:
            if (r2 < 0) goto L3c
            if (r6 == 0) goto L33
            java.util.ArrayList r5 = r4.l
            goto L35
        L33:
            java.util.ArrayList r5 = r4.k
        L35:
            java.lang.Object r5 = r5.get(r2)
            androidx.transition.I r5 = (androidx.transition.I) r5
            return r5
        L3c:
            r5 = 0
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.transition.y.p(android.view.View, boolean):androidx.transition.I");
    }

    public final y q() {
        F f = this.i;
        return f != null ? f.q() : this;
    }

    public String[] s() {
        return null;
    }

    public final I t(View view, boolean z) {
        F f = this.i;
        if (f != null) {
            return f.t(view, z);
        }
        return (I) ((C0208f) (z ? this.g : this.h).b).get(view);
    }

    public final String toString() {
        return P("");
    }

    public boolean u() {
        return !this.n.isEmpty();
    }

    public abstract boolean v();

    public boolean w(I i, I i2) {
        if (i != null && i2 != null) {
            String[] strArrS = s();
            if (strArrS != null) {
                for (String str : strArrS) {
                    if (y(i, i2, str)) {
                        return true;
                    }
                }
            } else {
                Iterator it2 = i.a.keySet().iterator();
                while (it2.hasNext()) {
                    if (y(i, i2, (String) it2.next())) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    public final boolean x(View view) {
        int id = view.getId();
        ArrayList arrayList = this.e;
        int size = arrayList.size();
        ArrayList arrayList2 = this.f;
        return (size == 0 && arrayList2.size() == 0) || arrayList.contains(Integer.valueOf(id)) || arrayList2.contains(view);
    }

    public final void z(y yVar, x xVar, boolean z) {
        y yVar2 = this.s;
        if (yVar2 != null) {
            yVar2.z(yVar, xVar, z);
        }
        ArrayList arrayList = this.t;
        if (arrayList == null || arrayList.isEmpty()) {
            return;
        }
        int size = this.t.size();
        InterfaceC1419w[] interfaceC1419wArr = this.m;
        if (interfaceC1419wArr == null) {
            interfaceC1419wArr = new InterfaceC1419w[size];
        }
        this.m = null;
        InterfaceC1419w[] interfaceC1419wArr2 = (InterfaceC1419w[]) this.t.toArray(interfaceC1419wArr);
        for (int i = 0; i < size; i++) {
            xVar.a(interfaceC1419wArr2[i], yVar, z);
            interfaceC1419wArr2[i] = null;
        }
        this.m = interfaceC1419wArr2;
    }
}

package androidx.transition;

import android.animation.TimeInterpolator;
import android.util.AndroidRuntimeException;
import android.view.View;
import android.view.ViewGroup;
import java.util.ArrayList;
import java.util.Iterator;

/* loaded from: classes.dex */
public class F extends y {
    public int H;
    public ArrayList F = new ArrayList();
    public boolean G = true;
    public boolean I = false;
    public int J = 0;

    @Override // androidx.transition.y
    public final void A(ViewGroup viewGroup) {
        super.A(viewGroup);
        int size = this.F.size();
        for (int i = 0; i < size; i++) {
            ((y) this.F.get(i)).A(viewGroup);
        }
    }

    @Override // androidx.transition.y
    public final void B() {
        this.y = 0L;
        E e = new E(this);
        for (int i = 0; i < this.F.size(); i++) {
            y yVar = (y) this.F.get(i);
            yVar.b(e);
            yVar.B();
            long j = yVar.y;
            if (this.G) {
                this.y = Math.max(this.y, j);
            } else {
                long j2 = this.y;
                yVar.A = j2;
                this.y = j2 + j;
            }
        }
    }

    @Override // androidx.transition.y
    public final y D(InterfaceC1419w interfaceC1419w) {
        super.D(interfaceC1419w);
        return this;
    }

    @Override // androidx.transition.y
    public final void E(View view) {
        for (int i = 0; i < this.F.size(); i++) {
            ((y) this.F.get(i)).E(view);
        }
        this.f.remove(view);
    }

    @Override // androidx.transition.y
    public final void F(View view) {
        super.F(view);
        int size = this.F.size();
        for (int i = 0; i < size; i++) {
            ((y) this.F.get(i)).F(view);
        }
    }

    @Override // androidx.transition.y
    public final void G() {
        if (this.F.isEmpty()) {
            O();
            o();
            return;
        }
        E e = new E();
        e.b = this;
        Iterator it2 = this.F.iterator();
        while (it2.hasNext()) {
            ((y) it2.next()).b(e);
        }
        this.H = this.F.size();
        if (this.G) {
            Iterator it3 = this.F.iterator();
            while (it3.hasNext()) {
                ((y) it3.next()).G();
            }
            return;
        }
        for (int i = 1; i < this.F.size(); i++) {
            ((y) this.F.get(i - 1)).b(new D((y) this.F.get(i), 0));
        }
        y yVar = (y) this.F.get(0);
        if (yVar != null) {
            yVar.G();
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:55:0x00c9  */
    /* JADX WARN: Removed duplicated region for block: B:74:? A[RETURN, SYNTHETIC] */
    @Override // androidx.transition.y
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void H(long r20, long r22) {
        /*
            Method dump skipped, instructions count: 225
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.transition.F.H(long, long):void");
    }

    @Override // androidx.transition.y
    public final void I(long j) {
        ArrayList arrayList;
        this.c = j;
        if (j < 0 || (arrayList = this.F) == null) {
            return;
        }
        int size = arrayList.size();
        for (int i = 0; i < size; i++) {
            ((y) this.F.get(i)).I(j);
        }
    }

    @Override // androidx.transition.y
    public final void J(C1405h c1405h) {
        this.w = c1405h;
        this.J |= 8;
        int size = this.F.size();
        for (int i = 0; i < size; i++) {
            ((y) this.F.get(i)).J(c1405h);
        }
    }

    @Override // androidx.transition.y
    public final void K(TimeInterpolator timeInterpolator) {
        this.J |= 1;
        ArrayList arrayList = this.F;
        if (arrayList != null) {
            int size = arrayList.size();
            for (int i = 0; i < size; i++) {
                ((y) this.F.get(i)).K(timeInterpolator);
            }
        }
        this.d = timeInterpolator;
    }

    @Override // androidx.transition.y
    public final void L(C1411n c1411n) {
        super.L(c1411n);
        this.J |= 4;
        if (this.F != null) {
            for (int i = 0; i < this.F.size(); i++) {
                ((y) this.F.get(i)).L(c1411n);
            }
        }
    }

    @Override // androidx.transition.y
    public final void M(C1411n c1411n) {
        this.v = c1411n;
        this.J |= 2;
        int size = this.F.size();
        for (int i = 0; i < size; i++) {
            ((y) this.F.get(i)).M(c1411n);
        }
    }

    @Override // androidx.transition.y
    public final void N(long j) {
        this.b = j;
    }

    @Override // androidx.transition.y
    public final String P(String str) {
        String strP = super.P(str);
        for (int i = 0; i < this.F.size(); i++) {
            StringBuilder sbX = android.support.v4.media.session.a.x(strP, "\n");
            sbX.append(((y) this.F.get(i)).P(str + "  "));
            strP = sbX.toString();
        }
        return strP;
    }

    public final void R(y yVar) {
        this.F.add(yVar);
        yVar.i = this;
        long j = this.c;
        if (j >= 0) {
            yVar.I(j);
        }
        if ((this.J & 1) != 0) {
            yVar.K(this.d);
        }
        if ((this.J & 2) != 0) {
            yVar.M(this.v);
        }
        if ((this.J & 4) != 0) {
            yVar.L(this.x);
        }
        if ((this.J & 8) != 0) {
            yVar.J(this.w);
        }
    }

    public final y S(int i) {
        if (i < 0 || i >= this.F.size()) {
            return null;
        }
        return (y) this.F.get(i);
    }

    public final void T(int i) {
        if (i == 0) {
            this.G = true;
        } else {
            if (i != 1) {
                throw new AndroidRuntimeException(android.support.v4.media.session.a.f(i, "Invalid parameter for TransitionSet ordering: "));
            }
            this.G = false;
        }
    }

    @Override // androidx.transition.y
    public final void c(View view) {
        for (int i = 0; i < this.F.size(); i++) {
            ((y) this.F.get(i)).c(view);
        }
        this.f.add(view);
    }

    @Override // androidx.transition.y
    public final void cancel() {
        super.cancel();
        int size = this.F.size();
        for (int i = 0; i < size; i++) {
            ((y) this.F.get(i)).cancel();
        }
    }

    @Override // androidx.transition.y
    public final void e(I i) {
        if (x(i.b)) {
            Iterator it2 = this.F.iterator();
            while (it2.hasNext()) {
                y yVar = (y) it2.next();
                if (yVar.x(i.b)) {
                    yVar.e(i);
                    i.c.add(yVar);
                }
            }
        }
    }

    @Override // androidx.transition.y
    public final void g(I i) {
        super.g(i);
        int size = this.F.size();
        for (int i2 = 0; i2 < size; i2++) {
            ((y) this.F.get(i2)).g(i);
        }
    }

    @Override // androidx.transition.y
    public final void h(I i) {
        if (x(i.b)) {
            Iterator it2 = this.F.iterator();
            while (it2.hasNext()) {
                y yVar = (y) it2.next();
                if (yVar.x(i.b)) {
                    yVar.h(i);
                    i.c.add(yVar);
                }
            }
        }
    }

    @Override // androidx.transition.y
    /* renamed from: l */
    public final y clone() {
        F f = (F) super.clone();
        f.F = new ArrayList();
        int size = this.F.size();
        for (int i = 0; i < size; i++) {
            y yVarClone = ((y) this.F.get(i)).clone();
            f.F.add(yVarClone);
            yVarClone.i = f;
        }
        return f;
    }

    @Override // androidx.transition.y
    public final void n(ViewGroup viewGroup, androidx.work.impl.model.i iVar, androidx.work.impl.model.i iVar2, ArrayList arrayList, ArrayList arrayList2) {
        long j = this.b;
        int size = this.F.size();
        for (int i = 0; i < size; i++) {
            y yVar = (y) this.F.get(i);
            if (j > 0 && (this.G || i == 0)) {
                long j2 = yVar.b;
                if (j2 > 0) {
                    yVar.N(j2 + j);
                } else {
                    yVar.N(j);
                }
            }
            yVar.n(viewGroup, iVar, iVar2, arrayList, arrayList2);
        }
    }

    @Override // androidx.transition.y
    public final boolean u() {
        for (int i = 0; i < this.F.size(); i++) {
            if (((y) this.F.get(i)).u()) {
                return true;
            }
        }
        return false;
    }

    @Override // androidx.transition.y
    public final boolean v() {
        int size = this.F.size();
        for (int i = 0; i < size; i++) {
            if (!((y) this.F.get(i)).v()) {
                return false;
            }
        }
        return true;
    }
}

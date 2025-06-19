package androidx.constraintlayout.core.widgets;

import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.ui.node.B;
import androidx.constraintlayout.core.widgets.analyzer.o;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;

/* loaded from: classes.dex */
public final class c {
    public int b;
    public boolean c;
    public final e d;
    public final int e;
    public c f;
    public androidx.constraintlayout.core.g i;
    public HashSet a = null;
    public int g = 0;
    public int h = Integer.MIN_VALUE;

    public c(e eVar, int i) {
        this.d = eVar;
        this.e = i;
    }

    public final void a(c cVar, int i) {
        b(cVar, i, Integer.MIN_VALUE, false);
    }

    public final boolean b(c cVar, int i, int i2, boolean z) {
        if (cVar == null) {
            j();
            return true;
        }
        if (!z && !i(cVar)) {
            return false;
        }
        this.f = cVar;
        if (cVar.a == null) {
            cVar.a = new HashSet();
        }
        HashSet hashSet = this.f.a;
        if (hashSet != null) {
            hashSet.add(this);
        }
        this.g = i;
        this.h = i2;
        return true;
    }

    public final void c(int i, o oVar, ArrayList arrayList) {
        HashSet hashSet = this.a;
        if (hashSet != null) {
            Iterator it2 = hashSet.iterator();
            while (it2.hasNext()) {
                androidx.constraintlayout.core.widgets.analyzer.i.b(((c) it2.next()).d, i, arrayList, oVar);
            }
        }
    }

    public final int d() {
        if (this.c) {
            return this.b;
        }
        return 0;
    }

    public final int e() {
        c cVar;
        if (this.d.j0 == 8) {
            return 0;
        }
        int i = this.h;
        return (i == Integer.MIN_VALUE || (cVar = this.f) == null || cVar.d.j0 != 8) ? this.g : i;
    }

    public final c f() {
        int i = this.e;
        int iK = AbstractC0147y.k(i);
        e eVar = this.d;
        switch (iK) {
            case 0:
            case 5:
            case 6:
            case 7:
            case 8:
                return null;
            case 1:
                return eVar.M;
            case 2:
                return eVar.N;
            case 3:
                return eVar.K;
            case 4:
                return eVar.L;
            default:
                throw new AssertionError(B.v(i));
        }
    }

    public final boolean g() {
        HashSet hashSet = this.a;
        if (hashSet == null) {
            return false;
        }
        Iterator it2 = hashSet.iterator();
        while (it2.hasNext()) {
            if (((c) it2.next()).f().h()) {
                return true;
            }
        }
        return false;
    }

    public final boolean h() {
        return this.f != null;
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Removed duplicated region for block: B:46:0x0063 A[RETURN] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean i(androidx.constraintlayout.core.widgets.c r11) {
        /*
            r10 = this;
            r0 = 0
            if (r11 != 0) goto L5
            goto L65
        L5:
            androidx.constraintlayout.core.widgets.e r1 = r11.d
            r2 = 6
            int r3 = r10.e
            r4 = 1
            int r11 = r11.e
            if (r11 != r3) goto L1c
            if (r3 != r2) goto L63
            boolean r11 = r1.F
            if (r11 == 0) goto L65
            androidx.constraintlayout.core.widgets.e r11 = r10.d
            boolean r11 = r11.F
            if (r11 != 0) goto L63
            goto L65
        L1c:
            int r5 = androidx.camera.camera2.internal.AbstractC0147y.k(r3)
            r6 = 4
            r7 = 2
            r8 = 9
            r9 = 8
            switch(r5) {
                case 0: goto L65;
                case 1: goto L53;
                case 2: goto L3f;
                case 3: goto L53;
                case 4: goto L3f;
                case 5: goto L3a;
                case 6: goto L33;
                case 7: goto L65;
                case 8: goto L65;
                default: goto L29;
            }
        L29:
            java.lang.AssertionError r11 = new java.lang.AssertionError
            java.lang.String r0 = androidx.compose.ui.node.B.v(r3)
            r11.<init>(r0)
            throw r11
        L33:
            if (r11 == r2) goto L65
            if (r11 == r9) goto L65
            if (r11 == r8) goto L65
            goto L63
        L3a:
            if (r11 == r7) goto L65
            if (r11 != r6) goto L63
            goto L65
        L3f:
            r2 = 3
            if (r11 == r2) goto L48
            r2 = 5
            if (r11 != r2) goto L46
            goto L48
        L46:
            r2 = r0
            goto L49
        L48:
            r2 = r4
        L49:
            boolean r1 = r1 instanceof androidx.constraintlayout.core.widgets.i
            if (r1 == 0) goto L52
            if (r2 != 0) goto L63
            if (r11 != r8) goto L65
            goto L63
        L52:
            return r2
        L53:
            if (r11 == r7) goto L5a
            if (r11 != r6) goto L58
            goto L5a
        L58:
            r2 = r0
            goto L5b
        L5a:
            r2 = r4
        L5b:
            boolean r1 = r1 instanceof androidx.constraintlayout.core.widgets.i
            if (r1 == 0) goto L64
            if (r2 != 0) goto L63
            if (r11 != r9) goto L65
        L63:
            return r4
        L64:
            return r2
        L65:
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.constraintlayout.core.widgets.c.i(androidx.constraintlayout.core.widgets.c):boolean");
    }

    public final void j() {
        HashSet hashSet;
        c cVar = this.f;
        if (cVar != null && (hashSet = cVar.a) != null) {
            hashSet.remove(this);
            if (this.f.a.size() == 0) {
                this.f.a = null;
            }
        }
        this.a = null;
        this.f = null;
        this.g = 0;
        this.h = Integer.MIN_VALUE;
        this.c = false;
        this.b = 0;
    }

    public final void k() {
        androidx.constraintlayout.core.g gVar = this.i;
        if (gVar == null) {
            this.i = new androidx.constraintlayout.core.g(1);
        } else {
            gVar.c();
        }
    }

    public final void l(int i) {
        this.b = i;
        this.c = true;
    }

    public final String toString() {
        return this.d.l0 + ":" + B.v(this.e);
    }
}

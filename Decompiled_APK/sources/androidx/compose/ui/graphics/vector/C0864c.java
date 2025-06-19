package androidx.compose.ui.graphics.vector;

import androidx.compose.animation.d0;
import androidx.compose.runtime.C0775b0;
import androidx.compose.ui.graphics.AbstractC0857q;
import androidx.compose.ui.graphics.C0850j;
import androidx.compose.ui.graphics.C0861v;
import androidx.compose.ui.graphics.X;
import java.util.ArrayList;
import java.util.List;
import kotlin.jvm.functions.Function1;

/* renamed from: androidx.compose.ui.graphics.vector.c, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0864c extends D {
    public float[] b;
    public C0850j h;
    public kotlin.jvm.internal.r i;
    public float l;
    public float m;
    public float n;
    public float q;
    public float r;
    public final ArrayList c = new ArrayList();
    public boolean d = true;
    public long e = C0861v.g;
    public List f = I.a;
    public boolean g = true;
    public final C0775b0 j = new C0775b0(this, 14);
    public String k = "";
    public float o = 1.0f;
    public float p = 1.0f;
    public boolean s = true;

    @Override // androidx.compose.ui.graphics.vector.D
    public final void a(androidx.compose.ui.graphics.drawscope.d dVar) {
        if (this.s) {
            float[] fArrA = this.b;
            if (fArrA == null) {
                fArrA = androidx.compose.ui.graphics.J.a();
                this.b = fArrA;
            } else {
                androidx.compose.ui.graphics.J.d(fArrA);
            }
            androidx.compose.ui.graphics.J.h(fArrA, this.q + this.m, this.r + this.n);
            androidx.compose.ui.graphics.J.e(this.l, fArrA);
            androidx.compose.ui.graphics.J.f(fArrA, this.o, this.p);
            androidx.compose.ui.graphics.J.h(fArrA, -this.m, -this.n);
            this.s = false;
        }
        if (this.g) {
            if (!this.f.isEmpty()) {
                C0850j c0850jH = this.h;
                if (c0850jH == null) {
                    c0850jH = androidx.compose.ui.graphics.F.h();
                    this.h = c0850jH;
                }
                AbstractC0863b.d(this.f, c0850jH);
            }
            this.g = false;
        }
        com.quizlet.data.repository.folderset.c cVarE0 = dVar.e0();
        long jR = cVarE0.r();
        cVarE0.o().e();
        try {
            androidx.appcompat.app.L l = (androidx.appcompat.app.L) cVarE0.b;
            float[] fArr = this.b;
            com.quizlet.data.repository.folderset.c cVar = (com.quizlet.data.repository.folderset.c) l.b;
            if (fArr != null) {
                cVar.o().j(fArr);
            }
            C0850j c0850j = this.h;
            if (!this.f.isEmpty() && c0850j != null) {
                cVar.o().i(c0850j);
            }
            ArrayList arrayList = this.c;
            int size = arrayList.size();
            for (int i = 0; i < size; i++) {
                ((D) arrayList.get(i)).a(dVar);
            }
        } finally {
            d0.y(cVarE0, jR);
        }
    }

    /* JADX WARN: Type inference failed for: r0v0, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.r] */
    @Override // androidx.compose.ui.graphics.vector.D
    public final Function1 b() {
        return this.i;
    }

    @Override // androidx.compose.ui.graphics.vector.D
    public final void d(C0775b0 c0775b0) {
        this.i = c0775b0;
    }

    public final void e(int i, D d) {
        ArrayList arrayList = this.c;
        if (i < arrayList.size()) {
            arrayList.set(i, d);
        } else {
            arrayList.add(d);
        }
        g(d);
        d.d(this.j);
        c();
    }

    public final void f(long j) {
        if (this.d && j != 16) {
            long j2 = this.e;
            if (j2 == 16) {
                this.e = j;
                return;
            }
            kotlin.collections.K k = I.a;
            if (C0861v.h(j2) == C0861v.h(j) && C0861v.g(j2) == C0861v.g(j) && C0861v.e(j2) == C0861v.e(j)) {
                return;
            }
            this.d = false;
            this.e = C0861v.g;
        }
    }

    public final void g(D d) {
        if (!(d instanceof C0870i)) {
            if (d instanceof C0864c) {
                C0864c c0864c = (C0864c) d;
                if (c0864c.d && this.d) {
                    f(c0864c.e);
                    return;
                } else {
                    this.d = false;
                    this.e = C0861v.g;
                    return;
                }
            }
            return;
        }
        C0870i c0870i = (C0870i) d;
        AbstractC0857q abstractC0857q = c0870i.b;
        if (this.d && abstractC0857q != null) {
            if (abstractC0857q instanceof X) {
                f(((X) abstractC0857q).a);
            } else {
                this.d = false;
                this.e = C0861v.g;
            }
        }
        AbstractC0857q abstractC0857q2 = c0870i.g;
        if (this.d && abstractC0857q2 != null) {
            if (abstractC0857q2 instanceof X) {
                f(((X) abstractC0857q2).a);
            } else {
                this.d = false;
                this.e = C0861v.g;
            }
        }
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("VGroup: ");
        sb.append(this.k);
        ArrayList arrayList = this.c;
        int size = arrayList.size();
        for (int i = 0; i < size; i++) {
            D d = (D) arrayList.get(i);
            sb.append("\t");
            sb.append(d.toString());
            sb.append("\n");
        }
        return sb.toString();
    }
}

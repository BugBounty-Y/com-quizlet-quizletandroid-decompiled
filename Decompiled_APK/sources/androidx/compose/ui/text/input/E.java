package androidx.compose.ui.text.input;

import android.graphics.Rect;
import android.view.Choreographer;
import android.view.View;
import android.view.inputmethod.InputMethodManager;
import androidx.compose.ui.platform.C0971v;
import com.google.android.gms.internal.mlkit_vision_barcode.C5;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class E implements u {
    public final View a;
    public final com.quizlet.data.repository.set.f b;
    public final F c;
    public boolean d;
    public kotlin.jvm.internal.r e;
    public kotlin.jvm.internal.r f;
    public A g;
    public m h;
    public final ArrayList i;
    public final Object j;
    public Rect k;
    public final C1002e l;
    public final androidx.compose.runtime.collection.b m;
    public C n;

    public E(View view, C0971v c0971v) {
        com.quizlet.data.repository.set.f fVar = new com.quizlet.data.repository.set.f(view);
        F f = new F(Choreographer.getInstance());
        this.a = view;
        this.b = fVar;
        this.c = f;
        this.e = C1001d.e;
        this.f = C1001d.f;
        this.g = new A(4, androidx.compose.ui.text.K.b, "");
        this.h = m.g;
        this.i = new ArrayList();
        this.j = kotlin.l.a(kotlin.m.c, new androidx.compose.ui.input.nestedscroll.b(this, 12));
        this.l = new C1002e(c0971v, fVar);
        this.m = new androidx.compose.runtime.collection.b(new D[16]);
    }

    @Override // androidx.compose.ui.text.input.u
    public final void a() {
        i(D.a);
    }

    @Override // androidx.compose.ui.text.input.u
    public final void b() {
        i(D.c);
    }

    @Override // androidx.compose.ui.text.input.u
    public final void c(A a, s sVar, androidx.compose.ui.text.H h, androidx.camera.lifecycle.f fVar, androidx.compose.ui.geometry.c cVar, androidx.compose.ui.geometry.c cVar2) {
        C1002e c1002e = this.l;
        synchronized (c1002e.c) {
            try {
                c1002e.j = a;
                c1002e.l = sVar;
                c1002e.k = h;
                c1002e.m = fVar;
                c1002e.n = cVar;
                c1002e.o = cVar2;
                if (c1002e.e || c1002e.d) {
                    c1002e.a();
                }
                Unit unit = Unit.a;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // androidx.compose.ui.text.input.u
    public final void d() {
        this.d = false;
        this.e = C1001d.g;
        this.f = C1001d.h;
        this.k = null;
        i(D.b);
    }

    @Override // androidx.compose.ui.text.input.u
    public final void e(A a, m mVar, androidx.activity.compose.g gVar, androidx.compose.foundation.text.D d) {
        this.d = true;
        this.g = a;
        this.h = mVar;
        this.e = gVar;
        this.f = d;
        i(D.a);
    }

    @Override // androidx.compose.ui.text.input.u
    public final void f() {
        i(D.d);
    }

    /* JADX WARN: Type inference failed for: r13v14, types: [java.lang.Object, kotlin.k] */
    /* JADX WARN: Type inference failed for: r13v22, types: [java.lang.Object, kotlin.k] */
    /* JADX WARN: Type inference failed for: r13v8, types: [java.lang.Object, kotlin.k] */
    /* JADX WARN: Type inference failed for: r6v3, types: [java.lang.Object, kotlin.k] */
    @Override // androidx.compose.ui.text.input.u
    public final void g(A a, A a2) {
        boolean z = (androidx.compose.ui.text.K.a(this.g.b, a2.b) && Intrinsics.b(this.g.c, a2.c)) ? false : true;
        this.g = a2;
        int size = this.i.size();
        for (int i = 0; i < size; i++) {
            v vVar = (v) ((WeakReference) this.i.get(i)).get();
            if (vVar != null) {
                vVar.d = a2;
            }
        }
        C1002e c1002e = this.l;
        synchronized (c1002e.c) {
            c1002e.j = null;
            c1002e.l = null;
            c1002e.k = null;
            c1002e.m = C1001d.b;
            c1002e.n = null;
            c1002e.o = null;
            Unit unit = Unit.a;
        }
        if (Intrinsics.b(a, a2)) {
            if (z) {
                com.quizlet.data.repository.set.f fVar = this.b;
                int iE = androidx.compose.ui.text.K.e(a2.b);
                int iD = androidx.compose.ui.text.K.d(a2.b);
                androidx.compose.ui.text.K k = this.g.c;
                int iE2 = k != null ? androidx.compose.ui.text.K.e(k.a) : -1;
                androidx.compose.ui.text.K k2 = this.g.c;
                ((InputMethodManager) fVar.c.getValue()).updateSelection((View) fVar.b, iE, iD, iE2, k2 != null ? androidx.compose.ui.text.K.d(k2.a) : -1);
                return;
            }
            return;
        }
        if (a != null && (!Intrinsics.b(a.a.a, a2.a.a) || (androidx.compose.ui.text.K.a(a.b, a2.b) && !Intrinsics.b(a.c, a2.c)))) {
            com.quizlet.data.repository.set.f fVar2 = this.b;
            ((InputMethodManager) fVar2.c.getValue()).restartInput((View) fVar2.b);
            return;
        }
        int size2 = this.i.size();
        for (int i2 = 0; i2 < size2; i2++) {
            v vVar2 = (v) ((WeakReference) this.i.get(i2)).get();
            if (vVar2 != null) {
                A a3 = this.g;
                com.quizlet.data.repository.set.f fVar3 = this.b;
                if (vVar2.h) {
                    vVar2.d = a3;
                    if (vVar2.f) {
                        ((InputMethodManager) fVar3.c.getValue()).updateExtractedText((View) fVar3.b, vVar2.e, C5.d(a3));
                    }
                    androidx.compose.ui.text.K k3 = a3.c;
                    int iE3 = k3 != null ? androidx.compose.ui.text.K.e(k3.a) : -1;
                    androidx.compose.ui.text.K k4 = a3.c;
                    int iD2 = k4 != null ? androidx.compose.ui.text.K.d(k4.a) : -1;
                    long j = a3.b;
                    ((InputMethodManager) fVar3.c.getValue()).updateSelection((View) fVar3.b, androidx.compose.ui.text.K.e(j), androidx.compose.ui.text.K.d(j), iE3, iD2);
                }
            }
        }
    }

    @Override // androidx.compose.ui.text.input.u
    public final void h(androidx.compose.ui.geometry.c cVar) {
        Rect rect;
        this.k = new Rect(kotlin.math.c.b(cVar.a), kotlin.math.c.b(cVar.b), kotlin.math.c.b(cVar.c), kotlin.math.c.b(cVar.d));
        if (!this.i.isEmpty() || (rect = this.k) == null) {
            return;
        }
        this.a.requestRectangleOnScreen(new Rect(rect));
    }

    public final void i(D d) {
        this.m.b(d);
        if (this.n == null) {
            C c = new C(this, 0);
            this.c.execute(c);
            this.n = c;
        }
    }
}

package androidx.compose.ui.graphics.vector;

import android.graphics.Matrix;
import android.graphics.Path;
import java.util.ArrayList;

/* renamed from: androidx.compose.ui.graphics.vector.g, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0868g {
    public final ArrayList a;

    public C0868g(int i) {
        switch (i) {
            case 1:
                this.a = new ArrayList();
                break;
            case 2:
                this.a = new ArrayList();
                break;
            default:
                this.a = new ArrayList(32);
                break;
        }
    }

    public void a(Path path) {
        ArrayList arrayList = this.a;
        for (int size = arrayList.size() - 1; size >= 0; size--) {
            com.airbnb.lottie.animation.content.t tVar = (com.airbnb.lottie.animation.content.t) arrayList.get(size);
            Matrix matrix = com.airbnb.lottie.utils.i.a;
            if (tVar != null && !tVar.a) {
                com.airbnb.lottie.utils.i.a(path, tVar.d.l() / 100.0f, tVar.e.l() / 100.0f, tVar.f.l() / 360.0f);
            }
        }
    }

    public void b() {
        this.a.add(C0872k.c);
    }

    public void c(float f, float f2, float f3, float f4, float f5, float f6) {
        this.a.add(new t(f, f2, f3, f4, f5, f6));
    }

    public void d(float f) {
        this.a.add(new u(f));
    }

    public void e(float f, float f2) {
        this.a.add(new n(f, f2));
    }

    public void f(float f, float f2) {
        this.a.add(new v(f, f2));
    }

    public void g(float f, float f2) {
        this.a.add(new o(f, f2));
    }

    public void h(float f, float f2, float f3, float f4) {
        this.a.add(new q(f, f2, f3, f4));
    }

    public void i(float f, float f2, float f3, float f4) {
        this.a.add(new y(f, f2, f3, f4));
    }

    public void j(float f) {
        this.a.add(new A(f));
    }
}

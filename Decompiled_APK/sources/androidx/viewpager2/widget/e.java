package androidx.viewpager2.widget;

import androidx.recyclerview.widget.AbstractC1365f0;
import androidx.work.impl.model.n;

/* loaded from: classes.dex */
public final class e extends AbstractC1365f0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ e(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // androidx.recyclerview.widget.AbstractC1365f0
    public final void a() {
        switch (this.a) {
            case 0:
                ViewPager2 viewPager2 = (ViewPager2) this.b;
                viewPager2.e = true;
                viewPager2.l.l = true;
                break;
            default:
                ((n) this.b).i();
                break;
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1365f0
    public final void b(int i, int i2) {
        a();
    }

    @Override // androidx.recyclerview.widget.AbstractC1365f0
    public final void c(int i, int i2, Object obj) {
        a();
    }

    @Override // androidx.recyclerview.widget.AbstractC1365f0
    public final void d(int i, int i2) {
        a();
    }

    @Override // androidx.recyclerview.widget.AbstractC1365f0
    public final void e(int i, int i2) {
        a();
    }

    @Override // androidx.recyclerview.widget.AbstractC1365f0
    public final void f(int i, int i2) {
        a();
    }
}

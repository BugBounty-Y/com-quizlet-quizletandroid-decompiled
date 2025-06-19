package androidx.viewpager2.widget;

import java.util.ArrayList;
import java.util.ConcurrentModificationException;
import java.util.Iterator;

/* loaded from: classes.dex */
public final class f extends i {
    public final /* synthetic */ int a;
    public final Object b;

    public /* synthetic */ f(ViewPager2 viewPager2, int i) {
        this.a = i;
        this.b = viewPager2;
    }

    @Override // androidx.viewpager2.widget.i
    public void a(int i) {
        switch (this.a) {
            case 0:
                if (i == 0) {
                    ((ViewPager2) this.b).d();
                    return;
                }
                return;
            case 1:
            default:
                return;
            case 2:
                try {
                    Iterator it2 = ((ArrayList) this.b).iterator();
                    while (it2.hasNext()) {
                        ((i) it2.next()).a(i);
                    }
                    return;
                } catch (ConcurrentModificationException e) {
                    throw new IllegalStateException("Adding and removing callbacks during dispatch to callbacks is not supported", e);
                }
        }
    }

    @Override // androidx.viewpager2.widget.i
    public void b(int i, float f, int i2) {
        switch (this.a) {
            case 2:
                try {
                    Iterator it2 = ((ArrayList) this.b).iterator();
                    while (it2.hasNext()) {
                        ((i) it2.next()).b(i, f, i2);
                    }
                    return;
                } catch (ConcurrentModificationException e) {
                    throw new IllegalStateException("Adding and removing callbacks during dispatch to callbacks is not supported", e);
                }
            default:
                return;
        }
    }

    @Override // androidx.viewpager2.widget.i
    public final void c(int i) {
        switch (this.a) {
            case 0:
                ViewPager2 viewPager2 = (ViewPager2) this.b;
                if (viewPager2.d != i) {
                    viewPager2.d = i;
                    viewPager2.t.i();
                    return;
                }
                return;
            case 1:
                ViewPager2 viewPager22 = (ViewPager2) this.b;
                viewPager22.clearFocus();
                if (viewPager22.hasFocus()) {
                    viewPager22.j.requestFocus(2);
                    return;
                }
                return;
            default:
                try {
                    Iterator it2 = ((ArrayList) this.b).iterator();
                    while (it2.hasNext()) {
                        ((i) it2.next()).c(i);
                    }
                    return;
                } catch (ConcurrentModificationException e) {
                    throw new IllegalStateException("Adding and removing callbacks during dispatch to callbacks is not supported", e);
                }
        }
    }

    public f() {
        this.a = 2;
        this.b = new ArrayList(3);
    }
}

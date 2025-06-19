package androidx.core.view;

import android.os.Build;
import android.view.View;
import java.nio.ByteBuffer;
import java.util.ConcurrentModificationException;

/* loaded from: classes.dex */
public abstract class I {
    public int a;
    public int b;
    public int c;
    public Object d;

    public I() {
        if (retrofit2.adapter.rxjava3.d.b == null) {
            retrofit2.adapter.rxjava3.d.b = new retrofit2.adapter.rxjava3.d(3);
        }
    }

    public int a(int i) {
        if (i < this.c) {
            return ((ByteBuffer) this.d).getShort(this.b + i);
        }
        return 0;
    }

    public void b() {
        if (((kotlin.collections.builders.h) this.d).h != this.c) {
            throw new ConcurrentModificationException();
        }
    }

    public abstract Object d(View view);

    public abstract void e(View view, Object obj);

    public void f() {
        while (true) {
            int i = this.a;
            kotlin.collections.builders.h hVar = (kotlin.collections.builders.h) this.d;
            if (i >= hVar.f || hVar.c[i] >= 0) {
                return;
            } else {
                this.a = i + 1;
            }
        }
    }

    public void g(View view, Object obj) {
        Object tag;
        if (Build.VERSION.SDK_INT >= this.b) {
            e(view, obj);
            return;
        }
        if (Build.VERSION.SDK_INT >= this.b) {
            tag = d(view);
        } else {
            tag = view.getTag(this.a);
            if (!((Class) this.d).isInstance(tag)) {
                tag = null;
            }
        }
        if (h(tag, obj)) {
            View.AccessibilityDelegate accessibilityDelegateD = V.d(view);
            C1038b c1038b = accessibilityDelegateD == null ? null : accessibilityDelegateD instanceof C1036a ? ((C1036a) accessibilityDelegateD).a : new C1038b(accessibilityDelegateD);
            if (c1038b == null) {
                c1038b = new C1038b();
            }
            V.o(view, c1038b);
            view.setTag(this.a, obj);
            V.i(this.c, view);
        }
    }

    public abstract boolean h(Object obj, Object obj2);

    public boolean hasNext() {
        return this.a < ((kotlin.collections.builders.h) this.d).f;
    }

    public void remove() {
        b();
        if (this.b == -1) {
            throw new IllegalStateException("Call next() before removing element from the iterator.");
        }
        kotlin.collections.builders.h hVar = (kotlin.collections.builders.h) this.d;
        hVar.d();
        hVar.n(this.b);
        this.b = -1;
        this.c = hVar.h;
    }
}

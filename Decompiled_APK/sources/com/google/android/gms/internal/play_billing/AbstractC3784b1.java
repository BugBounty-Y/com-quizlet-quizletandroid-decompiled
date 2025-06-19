package com.google.android.gms.internal.play_billing;

import androidx.camera.camera2.internal.AbstractC0147y;
import java.util.List;

/* renamed from: com.google.android.gms.internal.play_billing.b1, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3784b1 implements Cloneable {
    public final AbstractC3787c1 a;
    public AbstractC3787c1 b;

    public AbstractC3784b1(AbstractC3787c1 abstractC3787c1) {
        this.a = abstractC3787c1;
        if (abstractC3787c1.c()) {
            throw new IllegalArgumentException("Default instance must be immutable.");
        }
        this.b = (AbstractC3787c1) abstractC3787c1.d(4);
    }

    public static void b(int i, List list) {
        String strC = AbstractC0147y.c(list.size() - i, "Element at index ", " is null.");
        int size = list.size();
        while (true) {
            size--;
            if (size < i) {
                throw new NullPointerException(strC);
            }
            list.remove(size);
        }
    }

    public final AbstractC3787c1 c() {
        AbstractC3787c1 abstractC3787c1D = d();
        if (AbstractC3787c1.m(abstractC3787c1D, true)) {
            return abstractC3787c1D;
        }
        throw new zzji();
    }

    public final Object clone() {
        AbstractC3784b1 abstractC3784b1 = (AbstractC3784b1) this.a.d(5);
        abstractC3784b1.b = d();
        return abstractC3784b1;
    }

    public final AbstractC3787c1 d() {
        if (!this.b.c()) {
            return this.b;
        }
        AbstractC3787c1 abstractC3787c1 = this.b;
        abstractC3787c1.getClass();
        C3843v1.c.a(abstractC3787c1.getClass()).a(abstractC3787c1);
        abstractC3787c1.j();
        return this.b;
    }

    public final void e() {
        if (this.b.c()) {
            return;
        }
        AbstractC3787c1 abstractC3787c1 = (AbstractC3787c1) this.a.d(4);
        C3843v1.c.a(abstractC3787c1.getClass()).b(abstractC3787c1, this.b);
        this.b = abstractC3787c1;
    }
}

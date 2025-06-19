package com.google.android.gms.internal.ads;

import java.util.Iterator;
import java.util.NoSuchElementException;

/* renamed from: com.google.android.gms.internal.ads.pu, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2502pu extends Pu {
    public Object b;
    public int c;
    public final /* synthetic */ int d;
    public final Iterator e;
    public final /* synthetic */ Object f;

    public C2502pu() {
        super(0);
        this.c = 2;
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    @Override // java.util.Iterator
    public final boolean hasNext() {
        Object next;
        int i = this.c;
        if (i == 4) {
            throw new IllegalStateException();
        }
        int i2 = i - 1;
        if (i == 0) {
            throw null;
        }
        if (i2 == 0) {
            return true;
        }
        if (i2 != 2) {
            this.c = 4;
            switch (this.d) {
                case 0:
                    do {
                        Iterator it2 = this.e;
                        if (!it2.hasNext()) {
                            this.c = 3;
                            next = null;
                            break;
                        } else {
                            next = it2.next();
                        }
                    } while (!((InterfaceC2715ut) this.f).b(next));
                default:
                    do {
                        Iterator it3 = this.e;
                        if (!it3.hasNext()) {
                            this.c = 3;
                            next = null;
                            break;
                        } else {
                            next = it3.next();
                        }
                    } while (!((AbstractC2459ou) this.f).contains(next));
            }
            this.b = next;
            if (this.c != 3) {
                this.c = 1;
                return true;
            }
        }
        return false;
    }

    @Override // com.google.android.gms.internal.ads.Pu, java.util.Iterator
    public final Object next() {
        if (!hasNext()) {
            throw new NoSuchElementException();
        }
        this.c = 2;
        Object obj = this.b;
        this.b = null;
        return obj;
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public C2502pu(AbstractC2459ou abstractC2459ou, AbstractC2459ou abstractC2459ou2) {
        this();
        this.d = 1;
        this.f = abstractC2459ou2;
        this.e = abstractC2459ou.iterator();
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public C2502pu(Iterator it2, InterfaceC2715ut interfaceC2715ut) {
        this();
        this.d = 0;
        this.e = it2;
        this.f = interfaceC2715ut;
    }
}

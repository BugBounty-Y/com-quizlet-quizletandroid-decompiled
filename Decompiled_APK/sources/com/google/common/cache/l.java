package com.google.common.cache;

import java.util.AbstractQueue;
import java.util.Iterator;
import java.util.logging.Logger;

/* loaded from: classes2.dex */
public final class l extends AbstractQueue {
    public final /* synthetic */ int a;
    public final AbstractC3915i b;

    public l(int i) {
        this.a = i;
        switch (i) {
            case 1:
                C3916j c3916j = new C3916j(1);
                c3916j.b = c3916j;
                c3916j.c = c3916j;
                this.b = c3916j;
                break;
            default:
                C3916j c3916j2 = new C3916j(0);
                c3916j2.b = c3916j2;
                c3916j2.c = c3916j2;
                this.b = c3916j2;
                break;
        }
    }

    @Override // java.util.AbstractQueue, java.util.AbstractCollection, java.util.Collection
    public final void clear() {
        r rVar = r.a;
        AbstractC3915i abstractC3915i = this.b;
        switch (this.a) {
            case 0:
                C3916j c3916j = (C3916j) abstractC3915i;
                J j = c3916j.b;
                while (j != c3916j) {
                    J j2 = j.j();
                    Logger logger = I.u;
                    j.k(rVar);
                    j.n(rVar);
                    j = j2;
                }
                c3916j.b = c3916j;
                c3916j.c = c3916j;
                break;
            default:
                C3916j c3916j2 = (C3916j) abstractC3915i;
                J j3 = c3916j2.b;
                while (j3 != c3916j2) {
                    J jE = j3.e();
                    Logger logger2 = I.u;
                    j3.l(rVar);
                    j3.m(rVar);
                    j3 = jE;
                }
                c3916j2.b = c3916j2;
                c3916j2.c = c3916j2;
                break;
        }
    }

    @Override // java.util.AbstractCollection, java.util.Collection
    public final boolean contains(Object obj) {
        switch (this.a) {
            case 0:
                if (((J) obj).j() != r.a) {
                }
                break;
            default:
                if (((J) obj).e() != r.a) {
                }
                break;
        }
        return false;
    }

    @Override // java.util.AbstractCollection, java.util.Collection
    public final boolean isEmpty() {
        switch (this.a) {
            case 0:
                C3916j c3916j = (C3916j) this.b;
                if (c3916j.b == c3916j) {
                }
                break;
            default:
                C3916j c3916j2 = (C3916j) this.b;
                if (c3916j2.b == c3916j2) {
                }
                break;
        }
        return false;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.lang.Iterable
    public final Iterator iterator() {
        switch (this.a) {
            case 0:
                C3916j c3916j = (C3916j) this.b;
                J j = c3916j.b;
                if (j == c3916j) {
                    j = null;
                }
                return new C3917k(this, j, 0);
            default:
                C3916j c3916j2 = (C3916j) this.b;
                J j2 = c3916j2.b;
                if (j2 == c3916j2) {
                    j2 = null;
                }
                return new C3917k(this, j2, 1);
        }
    }

    @Override // java.util.Queue
    public final boolean offer(Object obj) {
        AbstractC3915i abstractC3915i = this.b;
        switch (this.a) {
            case 0:
                J j = (J) obj;
                J jA = j.a();
                J j2 = j.j();
                Logger logger = I.u;
                jA.k(j2);
                j2.n(jA);
                C3916j c3916j = (C3916j) abstractC3915i;
                J j3 = c3916j.c;
                j3.k(j);
                j.n(j3);
                j.k(c3916j);
                c3916j.c = j;
                break;
            default:
                J j4 = (J) obj;
                J jO = j4.o();
                J jE = j4.e();
                Logger logger2 = I.u;
                jO.l(jE);
                jE.m(jO);
                C3916j c3916j2 = (C3916j) abstractC3915i;
                J j5 = c3916j2.c;
                j5.l(j4);
                j4.m(j5);
                j4.l(c3916j2);
                c3916j2.c = j4;
                break;
        }
        return true;
    }

    @Override // java.util.Queue
    public final Object peek() {
        switch (this.a) {
            case 0:
                C3916j c3916j = (C3916j) this.b;
                J j = c3916j.b;
                if (j == c3916j) {
                    return null;
                }
                return j;
            default:
                C3916j c3916j2 = (C3916j) this.b;
                J j2 = c3916j2.b;
                if (j2 == c3916j2) {
                    return null;
                }
                return j2;
        }
    }

    @Override // java.util.Queue
    public final Object poll() {
        switch (this.a) {
            case 0:
                C3916j c3916j = (C3916j) this.b;
                J j = c3916j.b;
                if (j == c3916j) {
                    return null;
                }
                remove(j);
                return j;
            default:
                C3916j c3916j2 = (C3916j) this.b;
                J j2 = c3916j2.b;
                if (j2 == c3916j2) {
                    return null;
                }
                remove(j2);
                return j2;
        }
    }

    @Override // java.util.AbstractCollection, java.util.Collection
    public final boolean remove(Object obj) {
        r rVar = r.a;
        switch (this.a) {
            case 0:
                J j = (J) obj;
                J jA = j.a();
                J j2 = j.j();
                Logger logger = I.u;
                jA.k(j2);
                j2.n(jA);
                j.k(rVar);
                j.n(rVar);
                if (j2 != rVar) {
                    break;
                }
                break;
            default:
                J j3 = (J) obj;
                J jO = j3.o();
                J jE = j3.e();
                Logger logger2 = I.u;
                jO.l(jE);
                jE.m(jO);
                j3.l(rVar);
                j3.m(rVar);
                if (jE != rVar) {
                    break;
                }
                break;
        }
        return true;
    }

    @Override // java.util.AbstractCollection, java.util.Collection
    public final int size() {
        switch (this.a) {
            case 0:
                C3916j c3916j = (C3916j) this.b;
                int i = 0;
                for (J j = c3916j.b; j != c3916j; j = j.j()) {
                    i++;
                }
                return i;
            default:
                C3916j c3916j2 = (C3916j) this.b;
                int i2 = 0;
                for (J jE = c3916j2.b; jE != c3916j2; jE = jE.e()) {
                    i2++;
                }
                return i2;
        }
    }
}

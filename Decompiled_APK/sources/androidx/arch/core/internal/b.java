package androidx.arch.core.internal;

import java.util.Iterator;

/* loaded from: classes.dex */
public final class b extends e implements Iterator {
    public c a;
    public c b;
    public final /* synthetic */ int c;

    public b(c cVar, c cVar2, int i) {
        this.c = i;
        this.a = cVar2;
        this.b = cVar;
    }

    @Override // androidx.arch.core.internal.e
    public final void a(c cVar) {
        c cVar2;
        c cVarB = null;
        if (this.a == cVar && cVar == this.b) {
            this.b = null;
            this.a = null;
        }
        c cVar3 = this.a;
        if (cVar3 == cVar) {
            switch (this.c) {
                case 0:
                    cVar2 = cVar3.d;
                    break;
                default:
                    cVar2 = cVar3.c;
                    break;
            }
            this.a = cVar2;
        }
        c cVar4 = this.b;
        if (cVar4 == cVar) {
            c cVar5 = this.a;
            if (cVar4 != cVar5 && cVar5 != null) {
                cVarB = b(cVar4);
            }
            this.b = cVarB;
        }
    }

    public final c b(c cVar) {
        switch (this.c) {
            case 0:
                return cVar.c;
            default:
                return cVar.d;
        }
    }

    @Override // java.util.Iterator
    public final boolean hasNext() {
        return this.b != null;
    }

    @Override // java.util.Iterator
    public final Object next() {
        c cVar = this.b;
        c cVar2 = this.a;
        this.b = (cVar == cVar2 || cVar2 == null) ? null : b(cVar);
        return cVar;
    }
}

package androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableList;

import java.util.ConcurrentModificationException;
import java.util.NoSuchElementException;

/* loaded from: classes.dex */
public final class i extends a {
    public final g d;
    public int e;
    public k f;
    public int g;

    public i(g gVar, int i) {
        super(i, gVar.h, 0);
        this.d = gVar;
        this.e = gVar.h();
        this.g = -1;
        b();
    }

    public final void a() {
        if (this.e != this.d.h()) {
            throw new ConcurrentModificationException();
        }
    }

    @Override // androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableList.a, java.util.ListIterator
    public final void add(Object obj) {
        a();
        int i = this.b;
        g gVar = this.d;
        gVar.add(i, obj);
        this.b++;
        this.c = gVar.a();
        this.e = gVar.h();
        this.g = -1;
        b();
    }

    /* JADX WARN: Type inference failed for: r6v2 */
    /* JADX WARN: Type inference failed for: r6v3, types: [boolean, int] */
    /* JADX WARN: Type inference failed for: r6v4 */
    public final void b() {
        g gVar = this.d;
        Object[] objArr = gVar.f;
        if (objArr == null) {
            this.f = null;
            return;
        }
        int i = (gVar.h - 1) & (-32);
        int i2 = this.b;
        if (i2 > i) {
            i2 = i;
        }
        int i3 = (gVar.d / 5) + 1;
        k kVar = this.f;
        if (kVar == null) {
            this.f = new k(objArr, i2, i, i3);
            return;
        }
        kVar.b = i2;
        kVar.c = i;
        kVar.d = i3;
        if (kVar.e.length < i3) {
            kVar.e = new Object[i3];
        }
        kVar.e[0] = objArr;
        ?? r6 = i2 == i ? 1 : 0;
        kVar.f = r6;
        kVar.b(i2 - r6, 1);
    }

    @Override // java.util.ListIterator, java.util.Iterator
    public final Object next() {
        a();
        if (!hasNext()) {
            throw new NoSuchElementException();
        }
        int i = this.b;
        this.g = i;
        k kVar = this.f;
        g gVar = this.d;
        if (kVar == null) {
            Object[] objArr = gVar.g;
            this.b = i + 1;
            return objArr[i];
        }
        if (kVar.hasNext()) {
            this.b++;
            return kVar.next();
        }
        Object[] objArr2 = gVar.g;
        int i2 = this.b;
        this.b = i2 + 1;
        return objArr2[i2 - kVar.c];
    }

    @Override // java.util.ListIterator
    public final Object previous() {
        a();
        if (!hasPrevious()) {
            throw new NoSuchElementException();
        }
        int i = this.b;
        this.g = i - 1;
        k kVar = this.f;
        g gVar = this.d;
        if (kVar == null) {
            Object[] objArr = gVar.g;
            int i2 = i - 1;
            this.b = i2;
            return objArr[i2];
        }
        int i3 = kVar.c;
        if (i <= i3) {
            this.b = i - 1;
            return kVar.previous();
        }
        Object[] objArr2 = gVar.g;
        int i4 = i - 1;
        this.b = i4;
        return objArr2[i4 - i3];
    }

    @Override // androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableList.a, java.util.ListIterator, java.util.Iterator
    public final void remove() {
        a();
        int i = this.g;
        if (i == -1) {
            throw new IllegalStateException();
        }
        g gVar = this.d;
        gVar.b(i);
        int i2 = this.g;
        if (i2 < this.b) {
            this.b = i2;
        }
        this.c = gVar.a();
        this.e = gVar.h();
        this.g = -1;
        b();
    }

    @Override // androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableList.a, java.util.ListIterator
    public final void set(Object obj) {
        a();
        int i = this.g;
        if (i == -1) {
            throw new IllegalStateException();
        }
        g gVar = this.d;
        gVar.set(i, obj);
        this.e = gVar.h();
        b();
    }
}

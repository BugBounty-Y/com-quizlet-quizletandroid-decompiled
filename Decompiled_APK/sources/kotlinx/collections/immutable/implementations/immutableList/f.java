package kotlinx.collections.immutable.implementations.immutableList;

import java.util.ConcurrentModificationException;
import java.util.NoSuchElementException;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class f extends androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableList.a {
    public final d d;
    public int e;
    public h f;
    public int g;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public f(d builder, int i) {
        super(i, builder.f, 1);
        Intrinsics.checkNotNullParameter(builder, "builder");
        this.d = builder;
        this.e = builder.h();
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
        d dVar = this.d;
        dVar.add(i, obj);
        this.b++;
        this.c = dVar.a();
        this.e = dVar.h();
        this.g = -1;
        b();
    }

    /* JADX WARN: Type inference failed for: r6v3 */
    /* JADX WARN: Type inference failed for: r6v4, types: [boolean, int] */
    /* JADX WARN: Type inference failed for: r6v5 */
    public final void b() {
        d dVar = this.d;
        Object[] root = dVar.d;
        if (root == null) {
            this.f = null;
            return;
        }
        int i = (dVar.f - 1) & (-32);
        int i2 = this.b;
        if (i2 > i) {
            i2 = i;
        }
        int i3 = (dVar.a / 5) + 1;
        h hVar = this.f;
        if (hVar == null) {
            this.f = new h(root, i2, i, i3);
            return;
        }
        Intrinsics.checkNotNullParameter(root, "root");
        hVar.b = i2;
        hVar.c = i;
        hVar.d = i3;
        if (hVar.e.length < i3) {
            hVar.e = new Object[i3];
        }
        hVar.e[0] = root;
        ?? r6 = i2 == i ? 1 : 0;
        hVar.f = r6;
        hVar.b(i2 - r6, 1);
    }

    @Override // java.util.ListIterator, java.util.Iterator
    public final Object next() {
        a();
        if (!hasNext()) {
            throw new NoSuchElementException();
        }
        int i = this.b;
        this.g = i;
        h hVar = this.f;
        d dVar = this.d;
        if (hVar == null) {
            Object[] objArr = dVar.e;
            this.b = i + 1;
            return objArr[i];
        }
        if (hVar.hasNext()) {
            this.b++;
            return hVar.next();
        }
        Object[] objArr2 = dVar.e;
        int i2 = this.b;
        this.b = i2 + 1;
        return objArr2[i2 - hVar.c];
    }

    @Override // java.util.ListIterator
    public final Object previous() {
        a();
        if (!hasPrevious()) {
            throw new NoSuchElementException();
        }
        int i = this.b;
        this.g = i - 1;
        h hVar = this.f;
        d dVar = this.d;
        if (hVar == null) {
            Object[] objArr = dVar.e;
            int i2 = i - 1;
            this.b = i2;
            return objArr[i2];
        }
        int i3 = hVar.c;
        if (i <= i3) {
            this.b = i - 1;
            return hVar.previous();
        }
        Object[] objArr2 = dVar.e;
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
        d dVar = this.d;
        dVar.b(i);
        int i2 = this.g;
        if (i2 < this.b) {
            this.b = i2;
        }
        this.c = dVar.a();
        this.e = dVar.h();
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
        d dVar = this.d;
        dVar.set(i, obj);
        this.e = dVar.h();
        b();
    }
}

package androidx.collection;

import java.util.Collection;
import java.util.Iterator;
import java.util.Set;
import kotlin.jvm.internal.AbstractC4958q;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class M implements kotlin.jvm.internal.markers.f, Set, kotlin.jvm.internal.markers.a {
    public final J a;
    public final J b;

    public M(J parent) {
        Intrinsics.checkNotNullParameter(parent, "parent");
        Intrinsics.checkNotNullParameter(parent, "parent");
        this.a = parent;
        this.b = parent;
    }

    @Override // java.util.Set, java.util.Collection
    public final boolean add(Object obj) {
        return this.b.a(obj);
    }

    @Override // java.util.Set, java.util.Collection
    public final boolean addAll(Collection elements) {
        Intrinsics.checkNotNullParameter(elements, "elements");
        Collection elements2 = elements;
        J j = this.b;
        j.getClass();
        Intrinsics.checkNotNullParameter(elements2, "elements");
        int i = j.d;
        Collection elements3 = elements2;
        Intrinsics.checkNotNullParameter(elements3, "elements");
        for (Object obj : elements3) {
            j.b[j.d(obj)] = obj;
        }
        return i != j.d;
    }

    @Override // java.util.Set, java.util.Collection
    public final void clear() {
        this.b.b();
    }

    @Override // java.util.Set, java.util.Collection
    public final boolean contains(Object obj) {
        return this.a.c(obj);
    }

    @Override // java.util.Set, java.util.Collection
    public final boolean containsAll(Collection elements) {
        Intrinsics.checkNotNullParameter(elements, "elements");
        Iterator it2 = elements.iterator();
        while (it2.hasNext()) {
            if (!this.a.c(it2.next())) {
                return false;
            }
        }
        return true;
    }

    @Override // java.util.Set, java.util.Collection
    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        return Intrinsics.b(this.a, ((M) obj).a);
    }

    @Override // java.util.Set, java.util.Collection
    public final int hashCode() {
        return this.a.hashCode();
    }

    @Override // java.util.Set, java.util.Collection
    public final boolean isEmpty() {
        return this.a.g();
    }

    @Override // java.util.Set, java.util.Collection, java.lang.Iterable
    public final Iterator iterator() {
        return new L(this);
    }

    @Override // java.util.Set, java.util.Collection
    public final boolean remove(Object obj) {
        return this.b.j(obj);
    }

    /* JADX WARN: Code restructure failed: missing block: B:18:0x0099, code lost:
    
        if (((r5 & ((~r5) << 6)) & r12) == 0) goto L22;
     */
    /* JADX WARN: Code restructure failed: missing block: B:19:0x009b, code lost:
    
        r14 = -1;
     */
    @Override // java.util.Set, java.util.Collection
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean removeAll(java.util.Collection r21) {
        /*
            r20 = this;
            r0 = r21
            java.lang.String r1 = "elements"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r0, r1)
            java.lang.Iterable r0 = (java.lang.Iterable) r0
            r2 = r20
            androidx.collection.J r3 = r2.b
            r3.getClass()
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r0, r1)
            int r4 = r3.d
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r0, r1)
            java.util.Iterator r0 = r0.iterator()
        L1c:
            boolean r1 = r0.hasNext()
            r5 = 1
            r6 = 0
            if (r1 == 0) goto Laa
            java.lang.Object r1 = r0.next()
            if (r1 == 0) goto L2f
            int r7 = r1.hashCode()
            goto L30
        L2f:
            r7 = r6
        L30:
            r8 = -862048943(0xffffffffcc9e2d51, float:-8.293031E7)
            int r7 = r7 * r8
            int r8 = r7 << 16
            r7 = r7 ^ r8
            r8 = r7 & 127(0x7f, float:1.78E-43)
            int r9 = r3.c
            int r7 = r7 >>> 7
            r7 = r7 & r9
        L3e:
            long[] r10 = r3.a
            int r11 = r7 >> 3
            r12 = r7 & 7
            int r12 = r12 << 3
            r13 = r10[r11]
            long r13 = r13 >>> r12
            int r11 = r11 + r5
            r15 = r10[r11]
            int r10 = 64 - r12
            long r10 = r15 << r10
            r21 = r5
            r15 = r6
            long r5 = (long) r12
            long r5 = -r5
            r12 = 63
            long r5 = r5 >> r12
            long r5 = r5 & r10
            long r5 = r5 | r13
            long r10 = (long) r8
            r12 = 72340172838076673(0x101010101010101, double:7.748604185489348E-304)
            long r10 = r10 * r12
            long r10 = r10 ^ r5
            long r12 = r10 - r12
            long r10 = ~r10
            long r10 = r10 & r12
            r12 = -9187201950435737472(0x8080808080808080, double:-2.937446524422997E-306)
            long r10 = r10 & r12
        L6c:
            r16 = 0
            int r14 = (r10 > r16 ? 1 : (r10 == r16 ? 0 : -1))
            if (r14 == 0) goto L8f
            int r14 = java.lang.Long.numberOfTrailingZeros(r10)
            int r14 = r14 >> 3
            int r14 = r14 + r7
            r14 = r14 & r9
            r18 = r12
            java.lang.Object[] r12 = r3.b
            r12 = r12[r14]
            boolean r12 = kotlin.jvm.internal.Intrinsics.b(r12, r1)
            if (r12 == 0) goto L87
            goto L9c
        L87:
            r12 = 1
            long r12 = r10 - r12
            long r10 = r10 & r12
            r12 = r18
            goto L6c
        L8f:
            r18 = r12
            long r10 = ~r5
            r12 = 6
            long r10 = r10 << r12
            long r5 = r5 & r10
            long r5 = r5 & r18
            int r5 = (r5 > r16 ? 1 : (r5 == r16 ? 0 : -1))
            if (r5 == 0) goto La3
            r14 = -1
        L9c:
            if (r14 < 0) goto L1c
            r3.k(r14)
            goto L1c
        La3:
            int r6 = r15 + 8
            int r7 = r7 + r6
            r7 = r7 & r9
            r5 = r21
            goto L3e
        Laa:
            r21 = r5
            int r0 = r3.d
            if (r4 == r0) goto Lb1
            return r21
        Lb1:
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.collection.M.removeAll(java.util.Collection):boolean");
    }

    /* JADX WARN: Removed duplicated region for block: B:16:0x0059  */
    @Override // java.util.Set, java.util.Collection
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean retainAll(java.util.Collection r19) {
        /*
            r18 = this;
            r0 = r19
            java.lang.String r1 = "elements"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r0, r1)
            r2 = r18
            androidx.collection.J r3 = r2.b
            r3.getClass()
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r0, r1)
            java.lang.Object[] r1 = r3.b
            int r4 = r3.d
            long[] r5 = r3.a
            int r6 = r5.length
            int r6 = r6 + (-2)
            if (r6 < 0) goto L5e
            r8 = 0
        L1d:
            r9 = r5[r8]
            long r11 = ~r9
            r13 = 7
            long r11 = r11 << r13
            long r11 = r11 & r9
            r13 = -9187201950435737472(0x8080808080808080, double:-2.937446524422997E-306)
            long r11 = r11 & r13
            int r11 = (r11 > r13 ? 1 : (r11 == r13 ? 0 : -1))
            if (r11 == 0) goto L59
            int r11 = r8 - r6
            int r11 = ~r11
            int r11 = r11 >>> 31
            r12 = 8
            int r11 = 8 - r11
            r13 = 0
        L37:
            if (r13 >= r11) goto L57
            r14 = 255(0xff, double:1.26E-321)
            long r14 = r14 & r9
            r16 = 128(0x80, double:6.3E-322)
            int r14 = (r14 > r16 ? 1 : (r14 == r16 ? 0 : -1))
            if (r14 >= 0) goto L53
            int r14 = r8 << 3
            int r14 = r14 + r13
            r15 = r0
            java.lang.Iterable r15 = (java.lang.Iterable) r15
            r7 = r1[r14]
            boolean r7 = kotlin.collections.CollectionsKt.F(r15, r7)
            if (r7 != 0) goto L53
            r3.k(r14)
        L53:
            long r9 = r9 >> r12
            int r13 = r13 + 1
            goto L37
        L57:
            if (r11 != r12) goto L5e
        L59:
            if (r8 == r6) goto L5e
            int r8 = r8 + 1
            goto L1d
        L5e:
            int r0 = r3.d
            if (r4 == r0) goto L64
            r7 = 1
            goto L65
        L64:
            r7 = 0
        L65:
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.collection.M.retainAll(java.util.Collection):boolean");
    }

    @Override // java.util.Set, java.util.Collection
    public final int size() {
        return this.a.d;
    }

    @Override // java.util.Set, java.util.Collection
    public final Object[] toArray() {
        return AbstractC4958q.a(this);
    }

    public final String toString() {
        return this.a.toString();
    }

    @Override // java.util.Set, java.util.Collection
    public final Object[] toArray(Object[] array) {
        Intrinsics.checkNotNullParameter(array, "array");
        return AbstractC4958q.b(this, array);
    }
}

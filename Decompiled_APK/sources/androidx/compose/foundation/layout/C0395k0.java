package androidx.compose.foundation.layout;

import androidx.compose.ui.layout.InterfaceC0894o;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.internal.mlkit_vision_barcode.L5;
import java.util.ArrayList;
import java.util.List;
import java.util.NoSuchElementException;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import kotlin.ranges.IntRange;

/* renamed from: androidx.compose.foundation.layout.k0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0395k0 implements androidx.compose.ui.layout.N, InterfaceC0387g0 {
    public final boolean a;
    public final InterfaceC0388h b;
    public final InterfaceC0394k c;
    public final float d;
    public final AbstractC0382e e;
    public final float f;
    public final int g;
    public final C0381d0 h;
    public final kotlin.jvm.internal.r i;
    public final kotlin.jvm.internal.r j;
    public final kotlin.jvm.internal.r k;

    public C0395k0(boolean z, InterfaceC0388h interfaceC0388h, InterfaceC0394k interfaceC0394k, float f, AbstractC0382e abstractC0382e, float f2, int i, C0381d0 c0381d0) {
        this.a = z;
        this.b = interfaceC0388h;
        this.c = interfaceC0394k;
        this.d = f;
        this.e = abstractC0382e;
        this.f = f2;
        this.g = i;
        this.h = c0381d0;
        this.i = z ? C0393j0.b : C0393j0.c;
        this.j = z ? C0393j0.d : C0393j0.e;
        this.k = z ? C0393j0.f : C0393j0.g;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C0395k0)) {
            return false;
        }
        C0395k0 c0395k0 = (C0395k0) obj;
        return this.a == c0395k0.a && this.b.equals(c0395k0.b) && this.c.equals(c0395k0.c) && androidx.compose.ui.unit.e.a(this.d, c0395k0.d) && Intrinsics.b(this.e, c0395k0.e) && androidx.compose.ui.unit.e.a(this.f, c0395k0.f) && this.g == c0395k0.g && Intrinsics.b(this.h, c0395k0.h);
    }

    @Override // androidx.compose.foundation.layout.InterfaceC0387g0
    public final AbstractC0382e f() {
        return this.e;
    }

    @Override // androidx.compose.foundation.layout.InterfaceC0387g0
    public final InterfaceC0388h g() {
        return this.b;
    }

    @Override // androidx.compose.foundation.layout.InterfaceC0387g0
    public final InterfaceC0394k h() {
        return this.c;
    }

    public final int hashCode() {
        return this.h.hashCode() + androidx.compose.animation.d0.b(SubsamplingScaleImageView.TILE_SIZE_AUTO, androidx.compose.animation.d0.b(this.g, android.support.v4.media.session.a.b((this.e.hashCode() + android.support.v4.media.session.a.b((this.c.hashCode() + ((this.b.hashCode() + (Boolean.hashCode(this.a) * 31)) * 31)) * 31, this.d, 31)) * 31, this.f, 31), 31), 31);
    }

    @Override // androidx.compose.foundation.layout.InterfaceC0387g0
    public final boolean i() {
        return this.a;
    }

    /* JADX WARN: Type inference failed for: r1v0, types: [kotlin.jvm.functions.c, kotlin.jvm.internal.r] */
    /* JADX WARN: Type inference failed for: r2v0, types: [kotlin.jvm.functions.c, kotlin.jvm.internal.r] */
    public final int j(List list, int i, int i2, int i3, int i4, C0381d0 c0381d0) {
        return (int) (AbstractC0377b0.d(list, this.k, this.j, i, i2, i3, i4, c0381d0) >> 32);
    }

    /* JADX WARN: Type inference failed for: r0v0, types: [kotlin.jvm.functions.c, kotlin.jvm.internal.r] */
    public final int k(int i, int i2, List list) {
        ?? r0 = this.i;
        int size = list.size();
        int i3 = 0;
        int iMax = 0;
        int i4 = 0;
        int i5 = 0;
        while (i3 < size) {
            int iIntValue = ((Number) r0.invoke((androidx.compose.ui.layout.J) list.get(i3), Integer.valueOf(i3), Integer.valueOf(i))).intValue() + i2;
            int i6 = i3 + 1;
            if (i6 - i4 == this.g || i6 == list.size()) {
                iMax = Math.max(iMax, (i5 + iIntValue) - i2);
                i5 = 0;
                i4 = i3;
            } else {
                i5 += iIntValue;
            }
            i3 = i6;
        }
        return iMax;
    }

    /* JADX WARN: Type inference failed for: r2v0, types: [kotlin.jvm.functions.c, kotlin.jvm.internal.r] */
    /* JADX WARN: Type inference failed for: r3v0, types: [kotlin.jvm.functions.c, kotlin.jvm.internal.r] */
    public final int l(List list, int i, int i2, int i3, int i4, C0381d0 c0381d0) {
        ?? r2 = this.k;
        ?? r3 = this.j;
        if (list.isEmpty()) {
            return 0;
        }
        int size = list.size();
        int[] iArr = new int[size];
        for (int i5 = 0; i5 < size; i5++) {
            iArr[i5] = 0;
        }
        int size2 = list.size();
        int[] iArr2 = new int[size2];
        for (int i6 = 0; i6 < size2; i6++) {
            iArr2[i6] = 0;
        }
        int size3 = list.size();
        for (int i7 = 0; i7 < size3; i7++) {
            androidx.compose.ui.layout.J j = (androidx.compose.ui.layout.J) list.get(i7);
            int iIntValue = ((Number) r2.invoke(j, Integer.valueOf(i7), Integer.valueOf(i))).intValue();
            iArr[i7] = iIntValue;
            iArr2[i7] = ((Number) r3.invoke(j, Integer.valueOf(i7), Integer.valueOf(iIntValue))).intValue();
        }
        List list2 = list;
        if (Integer.MAX_VALUE < list2.size()) {
            c0381d0.getClass();
        }
        if (Integer.MAX_VALUE >= list2.size()) {
            c0381d0.getClass();
        }
        int iMin = Math.min(SubsamplingScaleImageView.TILE_SIZE_AUTO, list2.size());
        Intrinsics.checkNotNullParameter(iArr, "<this>");
        int i8 = 0;
        for (int i9 = 0; i9 < size; i9++) {
            i8 += iArr[i9];
        }
        int size4 = ((list2.size() - 1) * i2) + i8;
        if (size2 == 0) {
            throw new NoSuchElementException();
        }
        int i10 = iArr2[0];
        Intrinsics.checkNotNullParameter(iArr2, "<this>");
        kotlin.ranges.i it2 = new IntRange(1, size2 - 1, 1).iterator();
        while (it2.c) {
            int i11 = iArr2[it2.nextInt()];
            if (i10 < i11) {
                i10 = i11;
            }
        }
        if (size == 0) {
            throw new NoSuchElementException();
        }
        int i12 = iArr[0];
        Intrinsics.checkNotNullParameter(iArr, "<this>");
        kotlin.ranges.i it3 = new IntRange(1, size - 1, 1).iterator();
        while (it3.c) {
            int i13 = iArr[it3.nextInt()];
            if (i12 < i13) {
                i12 = i13;
            }
        }
        int i14 = size4;
        while (i12 <= size4 && i10 != i) {
            int i15 = (i12 + size4) / 2;
            long jD = AbstractC0377b0.d(list2, new Z(iArr, 0), new Z(iArr2, 1), i15, i2, i3, i4, c0381d0);
            i10 = (int) (jD >> 32);
            int i16 = (int) (jD & 4294967295L);
            if (i10 > i || i16 < iMin) {
                i12 = i15 + 1;
                if (i12 > size4) {
                    return i12;
                }
            } else {
                if (i10 >= i) {
                    return i15;
                }
                size4 = i15 - 1;
            }
            list2 = list;
            i14 = i15;
        }
        return i14;
    }

    @Override // androidx.compose.ui.layout.N
    public final int maxIntrinsicHeight(InterfaceC0894o interfaceC0894o, List list, int i) {
        List list2 = (List) CollectionsKt.O(1, list);
        androidx.compose.ui.layout.J j = list2 != null ? (androidx.compose.ui.layout.J) CollectionsKt.firstOrNull(list2) : null;
        List list3 = (List) CollectionsKt.O(2, list);
        androidx.compose.ui.layout.J j2 = list3 != null ? (androidx.compose.ui.layout.J) CollectionsKt.firstOrNull(list3) : null;
        this.h.c(j, j2, this.a, L5.b(i, 0, 13));
        boolean z = this.a;
        float f = this.d;
        if (z) {
            List list4 = (List) CollectionsKt.firstOrNull(list);
            if (list4 == null) {
                list4 = kotlin.collections.K.a;
            }
            return j(list4, i, interfaceC0894o.m0(f), interfaceC0894o.m0(this.f), this.g, this.h);
        }
        List list5 = (List) CollectionsKt.firstOrNull(list);
        if (list5 == null) {
            list5 = kotlin.collections.K.a;
        }
        return k(i, interfaceC0894o.m0(f), list5);
    }

    @Override // androidx.compose.ui.layout.N
    public final int maxIntrinsicWidth(InterfaceC0894o interfaceC0894o, List list, int i) {
        List list2 = (List) CollectionsKt.O(1, list);
        androidx.compose.ui.layout.J j = list2 != null ? (androidx.compose.ui.layout.J) CollectionsKt.firstOrNull(list2) : null;
        List list3 = (List) CollectionsKt.O(2, list);
        androidx.compose.ui.layout.J j2 = list3 != null ? (androidx.compose.ui.layout.J) CollectionsKt.firstOrNull(list3) : null;
        this.h.c(j, j2, this.a, L5.b(0, i, 7));
        boolean z = this.a;
        float f = this.d;
        if (z) {
            List list4 = (List) CollectionsKt.firstOrNull(list);
            if (list4 == null) {
                list4 = kotlin.collections.K.a;
            }
            return k(i, interfaceC0894o.m0(f), list4);
        }
        List list5 = (List) CollectionsKt.firstOrNull(list);
        if (list5 == null) {
            list5 = kotlin.collections.K.a;
        }
        return j(list5, i, interfaceC0894o.m0(f), interfaceC0894o.m0(this.f), this.g, this.h);
    }

    @Override // androidx.compose.ui.layout.N
    /* renamed from: measure-3p2s80s, reason: not valid java name */
    public final androidx.compose.ui.layout.L mo2measure3p2s80s(androidx.compose.ui.layout.M m, List list, long j) {
        if (this.g != 0 && !((ArrayList) list).isEmpty()) {
            int iG = androidx.compose.ui.unit.a.g(j);
            C0381d0 c0381d0 = this.h;
            if (iG != 0) {
                List list2 = (List) CollectionsKt.L(list);
                if (list2.isEmpty()) {
                    return m.n0(0, 0, kotlin.collections.V.c(), C0406q.g);
                }
                List list3 = (List) CollectionsKt.O(1, list);
                androidx.compose.ui.layout.J j2 = list3 != null ? (androidx.compose.ui.layout.J) CollectionsKt.firstOrNull(list3) : null;
                List list4 = (List) CollectionsKt.O(2, list);
                androidx.compose.ui.layout.J j3 = list4 != null ? (androidx.compose.ui.layout.J) CollectionsKt.firstOrNull(list4) : null;
                list2.size();
                c0381d0.getClass();
                this.h.b(this, j2, j3, j);
                return AbstractC0377b0.c(m, this, list2.iterator(), this.d, this.f, AbstractC0382e.l(this.a ? 1 : 2, j), this.g, this.h);
            }
            c0381d0.getClass();
        }
        return m.n0(0, 0, kotlin.collections.V.c(), C0406q.f);
    }

    @Override // androidx.compose.ui.layout.N
    public final int minIntrinsicHeight(InterfaceC0894o interfaceC0894o, List list, int i) {
        List list2 = (List) CollectionsKt.O(1, list);
        androidx.compose.ui.layout.J j = list2 != null ? (androidx.compose.ui.layout.J) CollectionsKt.firstOrNull(list2) : null;
        List list3 = (List) CollectionsKt.O(2, list);
        androidx.compose.ui.layout.J j2 = list3 != null ? (androidx.compose.ui.layout.J) CollectionsKt.firstOrNull(list3) : null;
        this.h.c(j, j2, this.a, L5.b(i, 0, 13));
        boolean z = this.a;
        float f = this.f;
        float f2 = this.d;
        if (z) {
            List list4 = (List) CollectionsKt.firstOrNull(list);
            if (list4 == null) {
                list4 = kotlin.collections.K.a;
            }
            return j(list4, i, interfaceC0894o.m0(f2), interfaceC0894o.m0(f), this.g, this.h);
        }
        List list5 = (List) CollectionsKt.firstOrNull(list);
        if (list5 == null) {
            list5 = kotlin.collections.K.a;
        }
        return l(list5, i, interfaceC0894o.m0(f2), interfaceC0894o.m0(f), this.g, this.h);
    }

    @Override // androidx.compose.ui.layout.N
    public final int minIntrinsicWidth(InterfaceC0894o interfaceC0894o, List list, int i) {
        List list2 = (List) CollectionsKt.O(1, list);
        androidx.compose.ui.layout.J j = list2 != null ? (androidx.compose.ui.layout.J) CollectionsKt.firstOrNull(list2) : null;
        List list3 = (List) CollectionsKt.O(2, list);
        androidx.compose.ui.layout.J j2 = list3 != null ? (androidx.compose.ui.layout.J) CollectionsKt.firstOrNull(list3) : null;
        this.h.c(j, j2, this.a, L5.b(0, i, 7));
        boolean z = this.a;
        float f = this.f;
        float f2 = this.d;
        if (z) {
            List list4 = (List) CollectionsKt.firstOrNull(list);
            if (list4 == null) {
                list4 = kotlin.collections.K.a;
            }
            return l(list4, i, interfaceC0894o.m0(f2), interfaceC0894o.m0(f), this.g, this.h);
        }
        List list5 = (List) CollectionsKt.firstOrNull(list);
        if (list5 == null) {
            list5 = kotlin.collections.K.a;
        }
        return j(list5, i, interfaceC0894o.m0(f2), interfaceC0894o.m0(f), this.g, this.h);
    }

    public final String toString() {
        return "FlowMeasurePolicy(isHorizontal=" + this.a + ", horizontalArrangement=" + this.b + ", verticalArrangement=" + this.c + ", mainAxisSpacing=" + ((Object) androidx.compose.ui.unit.e.b(this.d)) + ", crossAxisAlignment=" + this.e + ", crossAxisArrangementSpacing=" + ((Object) androidx.compose.ui.unit.e.b(this.f)) + ", maxItemsInMainAxis=" + this.g + ", maxLines=2147483647, overflow=" + this.h + ')';
    }
}

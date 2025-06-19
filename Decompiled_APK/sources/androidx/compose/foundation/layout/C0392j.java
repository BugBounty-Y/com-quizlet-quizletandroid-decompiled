package androidx.compose.foundation.layout;

import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.foundation.layout.j, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0392j implements InterfaceC0390i {
    public final float a;
    public final boolean b;
    public final kotlin.jvm.internal.r c;
    public final float d;

    /* JADX WARN: Multi-variable type inference failed */
    public C0392j(float f, boolean z, Function2 function2) {
        this.a = f;
        this.b = z;
        this.c = (kotlin.jvm.internal.r) function2;
        this.d = f;
    }

    @Override // androidx.compose.foundation.layout.InterfaceC0388h, androidx.compose.foundation.layout.InterfaceC0394k
    public final float a() {
        return this.d;
    }

    @Override // androidx.compose.foundation.layout.InterfaceC0394k
    public final void b(androidx.compose.ui.unit.b bVar, int i, int[] iArr, int[] iArr2) {
        c(bVar, i, iArr, androidx.compose.ui.unit.k.a, iArr2);
    }

    /* JADX WARN: Type inference failed for: r11v2, types: [kotlin.jvm.functions.Function2, kotlin.jvm.internal.r] */
    @Override // androidx.compose.foundation.layout.InterfaceC0388h
    public final void c(androidx.compose.ui.unit.b bVar, int i, int[] iArr, androidx.compose.ui.unit.k kVar, int[] iArr2) {
        int i2;
        int i3;
        if (iArr.length == 0) {
            return;
        }
        int iM0 = bVar.m0(this.a);
        boolean z = this.b && kVar == androidx.compose.ui.unit.k.b;
        C0380d c0380d = AbstractC0398m.a;
        if (z) {
            int length = iArr.length - 1;
            i2 = 0;
            i3 = 0;
            while (-1 < length) {
                int i4 = iArr[length];
                int iMin = Math.min(i2, i - i4);
                iArr2[length] = iMin;
                int iMin2 = Math.min(iM0, (i - iMin) - i4);
                int i5 = iArr2[length] + i4 + iMin2;
                length--;
                i3 = iMin2;
                i2 = i5;
            }
        } else {
            int length2 = iArr.length;
            int i6 = 0;
            i2 = 0;
            i3 = 0;
            int i7 = 0;
            while (i6 < length2) {
                int i8 = iArr[i6];
                int iMin3 = Math.min(i2, i - i8);
                iArr2[i7] = iMin3;
                int iMin4 = Math.min(iM0, (i - iMin3) - i8);
                int i9 = iArr2[i7] + i8 + iMin4;
                i6++;
                i3 = iMin4;
                i2 = i9;
                i7++;
            }
        }
        int i10 = i2 - i3;
        ?? r11 = this.c;
        if (r11 == 0 || i10 >= i) {
            return;
        }
        int iIntValue = ((Number) r11.invoke(Integer.valueOf(i - i10), kVar)).intValue();
        int length3 = iArr2.length;
        for (int i11 = 0; i11 < length3; i11++) {
            iArr2[i11] = iArr2[i11] + iIntValue;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C0392j)) {
            return false;
        }
        C0392j c0392j = (C0392j) obj;
        return androidx.compose.ui.unit.e.a(this.a, c0392j.a) && this.b == c0392j.b && Intrinsics.b(this.c, c0392j.c);
    }

    public final int hashCode() {
        int iG = androidx.compose.animation.d0.g(Float.hashCode(this.a) * 31, 31, this.b);
        kotlin.jvm.internal.r rVar = this.c;
        return iG + (rVar == null ? 0 : rVar.hashCode());
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(this.b ? "" : "Absolute");
        sb.append("Arrangement#spacedAligned(");
        sb.append((Object) androidx.compose.ui.unit.e.b(this.a));
        sb.append(", ");
        sb.append(this.c);
        sb.append(')');
        return sb.toString();
    }
}

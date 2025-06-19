package androidx.compose.material3.internal;

import androidx.compose.animation.d0;
import androidx.compose.material3.C0674l;
import androidx.compose.material3.X1;
import com.google.android.gms.internal.mlkit_vision_barcode.P5;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.material3.internal.z, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0661z implements androidx.compose.ui.window.x {
    public final long a;
    public final androidx.compose.ui.unit.b b;
    public final int c;
    public final C0674l d;
    public final C0637a e;
    public final C0637a f;
    public final a0 g;
    public final a0 h;
    public final C0638b i;
    public final C0638b j;
    public final C0638b k;
    public final b0 l;
    public final b0 m;

    public C0661z(long j, androidx.compose.ui.unit.b bVar, C0674l c0674l) {
        int iM0 = bVar.m0(X1.a);
        this.a = j;
        this.b = bVar;
        this.c = iM0;
        this.d = c0674l;
        int iM02 = bVar.m0(Float.intBitsToFloat((int) (j >> 32)));
        androidx.compose.ui.g gVar = androidx.compose.ui.b.m;
        this.e = new C0637a(gVar, gVar, iM02);
        androidx.compose.ui.g gVar2 = androidx.compose.ui.b.o;
        this.f = new C0637a(gVar2, gVar2, iM02);
        this.g = new a0(androidx.compose.ui.a.c);
        this.h = new a0(androidx.compose.ui.a.d);
        int iM03 = bVar.m0(Float.intBitsToFloat((int) (j & 4294967295L)));
        androidx.compose.ui.h hVar = androidx.compose.ui.b.j;
        androidx.compose.ui.h hVar2 = androidx.compose.ui.b.l;
        this.i = new C0638b(hVar, hVar2, iM03);
        this.j = new C0638b(hVar2, hVar, iM03);
        this.k = new C0638b(androidx.compose.ui.b.k, hVar, iM03);
        this.l = new b0(hVar, iM0);
        this.m = new b0(hVar2, iM0);
    }

    @Override // androidx.compose.ui.window.x
    public final long a(androidx.compose.ui.unit.i iVar, long j, androidx.compose.ui.unit.k kVar, long j2) {
        long j3;
        char c;
        int iA;
        int i;
        int i2;
        char c2 = 3;
        int iB = iVar.b() / 2;
        int i3 = iVar.a;
        int iA2 = iVar.a() / 2;
        int i4 = iVar.b;
        int i5 = (int) (j >> 32);
        List listJ = kotlin.collections.B.j(this.e, this.f, ((int) (P5.b(iB + i3, iA2 + i4) >> 32)) < i5 / 2 ? this.g : this.h);
        int size = listJ.size();
        int i6 = 0;
        while (true) {
            if (i6 >= size) {
                j3 = j;
                c = c2;
                iA = 0;
                break;
            }
            J j4 = (J) listJ.get(i6);
            int i7 = (int) (j2 >> 32);
            int i8 = size;
            c = c2;
            int i9 = i6;
            j3 = j;
            iA = j4.a(iVar, j3, i7, kVar);
            if (i9 == kotlin.collections.B.i(listJ) || (iA >= 0 && i7 + iA <= i5)) {
                break;
            }
            i6 = i9 + 1;
            size = i8;
            c2 = c;
        }
        int i10 = (int) (j3 & 4294967295L);
        b0 b0Var = ((int) (P5.b((iVar.b() / 2) + i3, (iVar.a() / 2) + i4) & 4294967295L)) < i10 / 2 ? this.l : this.m;
        C0638b c0638b = this.i;
        C0638b c0638b2 = this.j;
        C0638b c0638b3 = this.k;
        K[] kArr = new K[4];
        kArr[0] = c0638b;
        kArr[1] = c0638b2;
        kArr[2] = c0638b3;
        kArr[c] = b0Var;
        List listJ2 = kotlin.collections.B.j(kArr);
        int size2 = listJ2.size();
        for (int i11 = 0; i11 < size2; i11++) {
            int i12 = (int) (j2 & 4294967295L);
            int iA3 = ((K) listJ2.get(i11)).a(iVar, j3, i12);
            if (i11 == kotlin.collections.B.i(listJ2) || (iA3 >= (i2 = this.c) && i12 + iA3 <= i10 - i2)) {
                i = iA3;
                break;
            }
        }
        i = 0;
        long jB = P5.b(iA, i);
        int i13 = (int) (jB >> 32);
        int i14 = (int) (jB & 4294967295L);
        this.d.invoke(iVar, new androidx.compose.ui.unit.i(i13, i14, ((int) (j2 >> 32)) + i13, ((int) (j2 & 4294967295L)) + i14));
        return jB;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof C0661z) {
            C0661z c0661z = (C0661z) obj;
            if (this.a == c0661z.a && Intrinsics.b(this.b, c0661z.b) && this.c == c0661z.c && Intrinsics.b(this.d, c0661z.d)) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        return this.d.hashCode() + d0.b(this.c, (this.b.hashCode() + (Long.hashCode(this.a) * 31)) * 31, 31);
    }

    public final String toString() {
        return "DropdownMenuPositionProvider(contentOffset=" + ((Object) androidx.compose.ui.unit.f.a(this.a)) + ", density=" + this.b + ", verticalMargin=" + this.c + ", onPositionCalculated=" + this.d + ')';
    }
}

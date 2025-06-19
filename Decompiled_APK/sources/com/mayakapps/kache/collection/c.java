package com.mayakapps.kache.collection;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class c extends d {
    public final androidx.compose.ui.text.android.selection.f h;
    public final androidx.compose.ui.text.android.selection.f i;
    public final boolean j;
    public final androidx.compose.ui.text.android.selection.f k;

    public c(androidx.compose.ui.text.android.selection.f fVar, androidx.compose.ui.text.android.selection.f fVar2, boolean z) {
        super(6);
        this.h = fVar;
        this.i = fVar2;
        this.j = z;
        if (fVar == null && fVar2 == null) {
            throw new IllegalArgumentException("At least, one chain must be not null");
        }
        if (fVar != null) {
            fVar.e(this.d);
        }
        if (fVar2 != null) {
            fVar2.e(this.d);
        }
        if (z) {
            if (fVar == null) {
                Intrinsics.d(fVar2);
                fVar = fVar2;
            }
        } else if (fVar2 == null) {
            Intrinsics.d(fVar);
        } else {
            fVar = fVar2;
        }
        this.k = fVar;
    }

    @Override // com.mayakapps.kache.collection.d
    public final void a(int i) {
        androidx.compose.ui.text.android.selection.f fVar = this.h;
        if (fVar != null) {
            fVar.k(i);
        }
    }

    @Override // com.mayakapps.kache.collection.d
    public final void b(int i) {
        androidx.compose.ui.text.android.selection.f fVar = this.h;
        if (fVar != null) {
            fVar.a(i);
        }
        androidx.compose.ui.text.android.selection.f fVar2 = this.i;
        if (fVar2 != null) {
            fVar2.a(i);
        }
    }

    @Override // com.mayakapps.kache.collection.d
    public final void c(int i) {
        androidx.compose.ui.text.android.selection.f fVar = this.h;
        if (fVar != null) {
            fVar.l(i);
        }
        androidx.compose.ui.text.android.selection.f fVar2 = this.i;
        if (fVar2 != null) {
            fVar2.l(i);
        }
    }

    @Override // com.mayakapps.kache.collection.d
    public final void d(int i) {
        androidx.compose.ui.text.android.selection.f fVar = this.h;
        if (fVar != null) {
            fVar.k(i);
        }
        androidx.compose.ui.text.android.selection.f fVar2 = this.i;
        if (fVar2 != null) {
            fVar2.k(i);
        }
    }

    @Override // com.mayakapps.kache.collection.d
    public final void m(int i) {
        c cVar = this;
        Object[] objArr = cVar.b;
        Object[] objArr2 = cVar.c;
        androidx.compose.ui.text.android.selection.f fVar = cVar.j ? cVar.i : cVar.h;
        int[] newIndices = new int[cVar.d];
        i(i);
        Object[] objArr3 = cVar.b;
        Object[] objArr4 = cVar.c;
        int i2 = cVar.d;
        androidx.compose.ui.text.android.selection.f fVar2 = cVar.k;
        int i3 = fVar2.b;
        int[] iArr = (int[]) fVar2.d;
        Object[] objArrC = fVar2.c();
        fVar2.e(i2);
        Object[] objArrC2 = fVar2.c();
        while (i3 != -1) {
            int i4 = iArr[i3];
            Object obj = objArr[i3];
            int iHashCode = (obj != null ? obj.hashCode() : 0) * (-862048943);
            int i5 = iHashCode ^ (iHashCode << 16);
            int iF = cVar.f(i5 >>> 7);
            int i6 = i5 & 127;
            Object[] objArr5 = objArr;
            Object[] objArr6 = objArr2;
            long j = i6;
            long[] jArr = cVar.a;
            int i7 = iF >> 3;
            int i8 = (iF & 7) << 3;
            jArr[i7] = (jArr[i7] & (~(255 << i8))) | (j << i8);
            int i9 = cVar.d;
            int i10 = ((iF - 7) & i9) + (i9 & 7);
            int i11 = i10 >> 3;
            int i12 = (i10 & 7) << 3;
            jArr[i11] = (jArr[i11] & (~(255 << i12))) | (j << i12);
            objArr3[iF] = obj;
            objArr4[iF] = objArr6[i3];
            newIndices[i3] = iF;
            if (fVar2.b == -1) {
                fVar2.b = iF;
                fVar2.c = iF;
            } else {
                int[] iArr2 = (int[]) fVar2.d;
                int i13 = fVar2.c;
                iArr2[i13] = iF;
                ((int[]) fVar2.e)[iF] = i13;
                fVar2.c = iF;
            }
            if (objArrC2 != null) {
                objArrC2[iF] = objArrC != null ? objArrC[i3] : null;
            }
            cVar = this;
            i3 = i4;
            objArr = objArr5;
            objArr2 = objArr6;
        }
        if (fVar != null) {
            Intrinsics.checkNotNullParameter(newIndices, "newIndices");
            int i14 = fVar.b;
            int[] iArr3 = (int[]) fVar.d;
            Object[] objArrC3 = fVar.c();
            fVar.e(i);
            Object[] objArrC4 = fVar.c();
            if (i14 == -1) {
                fVar.b = -1;
                fVar.c = -1;
                return;
            }
            int i15 = newIndices[i14];
            fVar.b = i15;
            fVar.c = newIndices[fVar.c];
            int i16 = -1;
            while (i14 != -1) {
                int i17 = iArr3[i14];
                int i18 = newIndices[i17];
                ((int[]) fVar.d)[i15] = i18;
                ((int[]) fVar.e)[i15] = i16;
                if (objArrC4 != null) {
                    objArrC4[i18] = objArrC3 != null ? objArrC3[i14] : null;
                }
                i16 = i15;
                i14 = i17;
                i15 = i18;
            }
        }
    }
}

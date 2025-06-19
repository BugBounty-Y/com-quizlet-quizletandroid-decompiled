package androidx.compose.animation.core;

import androidx.collection.C0222u;
import androidx.collection.C0223v;
import java.util.Arrays;
import kotlin.collections.C4930v;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class S implements A {
    public final com.android.billingclient.api.s a;

    public S(com.android.billingclient.api.s sVar) {
        this.a = sVar;
    }

    @Override // androidx.compose.animation.core.A, androidx.compose.animation.core.InterfaceC0256n
    /* renamed from: f, reason: merged with bridge method [inline-methods] */
    public final androidx.camera.core.processing.e a(L0 l0) {
        int[] iArr;
        Object[] objArr;
        int[] iArr2;
        Object[] objArr2;
        int i;
        com.android.billingclient.api.s sVar = this.a;
        C0223v c0223v = (C0223v) sVar.c;
        C0222u c0222u = new C0222u(c0223v.e + 2);
        C0223v c0223v2 = new C0223v(c0223v.e);
        int[] iArr3 = c0223v.b;
        Object[] objArr3 = c0223v.c;
        long[] jArr = c0223v.a;
        int length = jArr.length - 2;
        if (length >= 0) {
            int i2 = 0;
            while (true) {
                long j = jArr[i2];
                if ((((~j) << 7) & j & (-9187201950435737472L)) != -9187201950435737472L) {
                    int i3 = 8;
                    int i4 = 8 - ((~(i2 - length)) >>> 31);
                    int i5 = 0;
                    while (i5 < i4) {
                        if ((j & 255) < 128) {
                            int i6 = (i2 << 3) + i5;
                            int i7 = iArr3[i6];
                            i = i3;
                            Q q = (Q) objArr3[i6];
                            c0222u.a(i7);
                            iArr2 = iArr3;
                            objArr2 = objArr3;
                            c0223v2.h(i7, new T0((AbstractC0267t) l0.a.invoke(q.a), q.b));
                        } else {
                            iArr2 = iArr3;
                            objArr2 = objArr3;
                            i = i3;
                        }
                        j >>= i;
                        i5++;
                        iArr3 = iArr2;
                        i3 = i;
                        objArr3 = objArr2;
                    }
                    iArr = iArr3;
                    objArr = objArr3;
                    if (i4 != i3) {
                        break;
                    }
                } else {
                    iArr = iArr3;
                    objArr = objArr3;
                }
                if (i2 == length) {
                    break;
                }
                i2++;
                iArr3 = iArr;
                objArr3 = objArr;
            }
        }
        if (!c0223v.b(0)) {
            int i8 = c0222u.b;
            if (i8 < 0) {
                androidx.collection.internal.a.d("Index must be between 0 and size");
                throw null;
            }
            c0222u.b(i8 + 1);
            int[] iArr4 = c0222u.a;
            int i9 = c0222u.b;
            if (i9 != 0) {
                C4930v.e(1, 0, i9, iArr4, iArr4);
            }
            iArr4[0] = 0;
            c0222u.b++;
        }
        if (!c0223v.b(sVar.b)) {
            c0222u.a(sVar.b);
        }
        int i10 = c0222u.b;
        if (i10 != 0) {
            int[] iArr5 = c0222u.a;
            Intrinsics.checkNotNullParameter(iArr5, "<this>");
            Arrays.sort(iArr5, 0, i10);
        }
        return new androidx.camera.core.processing.e(c0222u, c0223v2, sVar.b, C.d);
    }
}

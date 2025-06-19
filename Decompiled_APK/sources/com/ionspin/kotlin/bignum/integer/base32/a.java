package com.ionspin.kotlin.bignum.integer.base32;

import androidx.compose.animation.d0;
import com.ionspin.kotlin.bignum.integer.e;
import java.util.ArrayList;
import kotlin.A;
import kotlin.B;
import kotlin.C;
import kotlin.D;
import kotlin.collections.C4930v;
import kotlin.jvm.internal.Intrinsics;
import kotlin.z;

/* loaded from: classes2.dex */
public abstract class a {
    public static final int[] a = B.a(0);

    static {
        int[] storage = {1};
        Intrinsics.checkNotNullParameter(storage, "storage");
        int[] storage2 = {2};
        Intrinsics.checkNotNullParameter(storage2, "storage");
        int[] storage3 = {10};
        Intrinsics.checkNotNullParameter(storage3, "storage");
    }

    public static int a(int[] value) {
        Intrinsics.checkNotNullParameter(value, "value");
        if (value.length == 0) {
            return 0;
        }
        int i = value[value.length - 1];
        z zVar = A.b;
        return d0.c(value.length, 1, 32, 32 - f(i));
    }

    public static int b(int[] first, int[] second) {
        boolean z;
        boolean z2;
        Intrinsics.checkNotNullParameter(first, "first");
        Intrinsics.checkNotNullParameter(second, "second");
        int length = first.length - d(first);
        int length2 = second.length - d(second);
        if (length <= length2) {
            if (length2 <= length) {
                int i = length - 1;
                while (true) {
                    if (i < 0) {
                        z = false;
                        z2 = true;
                        break;
                    }
                    int i2 = first[i];
                    z zVar = A.b;
                    if (Integer.compareUnsigned(i2, second[i]) > 0) {
                        z2 = false;
                        z = true;
                        break;
                    }
                    if (Integer.compareUnsigned(first[i], second[i]) < 0) {
                        z2 = false;
                        z = false;
                        break;
                    }
                    i--;
                }
                if (z2) {
                    return 0;
                }
                if (z) {
                }
            }
            return -1;
        }
        return 1;
    }

    public static int c(int[] receiver, int[] other) {
        Intrinsics.checkNotNullParameter(receiver, "$receiver");
        Intrinsics.checkNotNullParameter(other, "other");
        return b(receiver, other);
    }

    public static int d(int[] bigInteger) {
        Intrinsics.checkNotNullParameter(bigInteger, "bigInteger");
        int length = bigInteger.length - 1;
        if (length <= 0) {
            return 0;
        }
        int i = bigInteger[length];
        z zVar = A.b;
        while (i == 0 && length > 0) {
            length--;
            i = bigInteger[length];
            z zVar2 = A.b;
        }
        int i2 = bigInteger[length];
        z zVar3 = A.b;
        if (i2 == 0) {
            length--;
        }
        return (bigInteger.length - length) - 1;
    }

    public static int[] e(int[] first, int[] second) {
        int[] iArr;
        int i;
        boolean z = true;
        Intrinsics.checkNotNullParameter(first, "$receiver");
        Intrinsics.checkNotNullParameter(second, "other");
        Intrinsics.checkNotNullParameter(first, "first");
        Intrinsics.checkNotNullParameter(second, "second");
        int[] iArrG = g(first);
        int[] iArrG2 = g(second);
        e eVar = b(iArrG, iArrG2) == 1 ? new e(Integer.valueOf(iArrG.length), Integer.valueOf(iArrG2.length), new B(iArrG), new B(iArrG2)) : new e(Integer.valueOf(iArrG2.length), Integer.valueOf(iArrG.length), new B(iArrG2), new B(iArrG));
        int iIntValue = ((Number) eVar.a).intValue();
        int iIntValue2 = ((Number) eVar.b).intValue();
        B b = (B) eVar.c;
        B b2 = (B) eVar.d;
        int i2 = iIntValue + 1;
        int[] storage = new int[i2];
        for (int i3 = 0; i3 < i2; i3++) {
            storage[i3] = 0;
        }
        Intrinsics.checkNotNullParameter(storage, "storage");
        int i4 = 0;
        long j = 0;
        while (true) {
            iArr = b.a;
            if (i4 >= iIntValue2) {
                break;
            }
            boolean z2 = z;
            if (i4 >= iArr.length) {
                System.out.println((Object) "Breakpoint");
            }
            if (i4 >= b2.a.length) {
                System.out.println((Object) "Breakpoint");
            }
            int i5 = iArr[i4];
            z zVar = A.b;
            long j2 = i5 & 4294967295L;
            C c = D.b;
            long j3 = (j2 - (r2[i4] & 4294967295L)) - j;
            storage[i4] = (int) j3;
            j = (j3 & 4294967296L) >>> 32;
            i4++;
            z = z2;
        }
        while (j != 0) {
            int i6 = iArr[i4];
            z zVar2 = A.b;
            C c2 = D.b;
            long j4 = (i6 & 4294967295L) - j;
            storage[i4] = (int) j4;
            j = (j4 & 4294967296L) >>> 32;
            i4++;
        }
        while (i4 < iIntValue) {
            int i7 = iArr[i4];
            z zVar3 = A.b;
            storage[i4] = i7;
            i4++;
        }
        ArrayList arrayList = new ArrayList();
        for (int i8 = 0; i8 < i2; i8++) {
            int i9 = storage[i8];
            if (i9 == 0) {
                arrayList.add(new A(i9));
            }
        }
        if (arrayList.isEmpty()) {
            return a;
        }
        while (true) {
            if (iIntValue < 0) {
                i = -1;
                break;
            }
            int i10 = storage[iIntValue];
            z zVar4 = A.b;
            if (i10 != 0) {
                i = iIntValue;
                break;
            }
            iIntValue--;
        }
        int[] storage2 = C4930v.l(0, i + 1, storage);
        Intrinsics.checkNotNullParameter(storage2, "storage");
        return storage2;
    }

    public static int f(int i) {
        int i2 = 16;
        int i3 = i >>> 16;
        z zVar = A.b;
        if (i3 != 0) {
            i = i3;
        } else {
            i2 = 32;
        }
        int i4 = i >>> 8;
        if (i4 != 0) {
            i2 -= 8;
            i = i4;
        }
        int i5 = i >>> 4;
        if (i5 != 0) {
            i2 -= 4;
            i = i5;
        }
        int i6 = i >>> 2;
        if (i6 != 0) {
            i2 -= 2;
            i = i6;
        }
        return (i >>> 1) != 0 ? i2 - 2 : i2 - i;
    }

    public static int[] g(int[] bigInteger) {
        Intrinsics.checkNotNullParameter(bigInteger, "bigInteger");
        int length = bigInteger.length;
        while (true) {
            length--;
            if (length < 0) {
                length = -1;
                break;
            }
            int i = bigInteger[length];
            z zVar = A.b;
            if (i != 0) {
                break;
            }
        }
        int i2 = length + 1;
        if (i2 == -1 || i2 == 0) {
            return a;
        }
        int[] storage = C4930v.l(0, i2, bigInteger);
        Intrinsics.checkNotNullParameter(storage, "storage");
        return storage;
    }

    public static int[] h(int[] operand, int i) {
        int i2;
        int i3;
        Intrinsics.checkNotNullParameter(operand, "$receiver");
        Intrinsics.checkNotNullParameter(operand, "operand");
        if (operand.length == 0 || i == 0) {
            return operand;
        }
        int length = operand.length;
        int i4 = operand[operand.length - 1];
        z zVar = A.b;
        int i5 = i / 32;
        int i6 = i % 32;
        int i7 = i6 > f(i4) ? i5 + 1 : i5;
        if (i6 == 0) {
            int length2 = operand.length + i7;
            int[] storage = new int[length2];
            for (int i8 = 0; i8 < length2; i8++) {
                if (i8 < 0 || i8 >= i5) {
                    i3 = operand[i8 - i5];
                    z zVar2 = A.b;
                } else {
                    i3 = 0;
                }
                storage[i8] = i3;
            }
            Intrinsics.checkNotNullParameter(storage, "storage");
            return storage;
        }
        int length3 = operand.length + i7;
        int[] storage2 = new int[length3];
        for (int i9 = 0; i9 < length3; i9++) {
            if (i9 >= 0 && i9 < i5) {
                i2 = 0;
            } else if (i9 == i5) {
                int i10 = operand[i9 - i5];
                z zVar3 = A.b;
                i2 = i10 << i6;
            } else {
                int i11 = i5 + 1;
                if (i9 < length + i5 && i11 <= i9) {
                    int i12 = i9 - i5;
                    int i13 = operand[i12];
                    z zVar4 = A.b;
                    i2 = (operand[i12 - 1] >>> (32 - i6)) | (i13 << i6);
                } else {
                    if (i9 != (length + i7) - 1) {
                        throw new RuntimeException(Intrinsics.k(Integer.valueOf(i9), "Invalid case "));
                    }
                    int i14 = operand[i9 - i7];
                    z zVar5 = A.b;
                    i2 = i14 >>> (32 - i6);
                }
            }
            storage2[i9] = i2;
        }
        Intrinsics.checkNotNullParameter(storage2, "storage");
        return storage2;
    }

    public static int[] i(int[] first, int i) {
        Intrinsics.checkNotNullParameter(first, "$receiver");
        Intrinsics.checkNotNullParameter(first, "first");
        int[] iArrA = B.a(first.length + 1);
        int length = first.length;
        if (length > 0) {
            int i2 = 0;
            while (true) {
                int i3 = i2 + 1;
                int i4 = first[i2];
                z zVar = A.b;
                C c = D.b;
                long j = (iArrA[i2] & 4294967295L) + (((int) (r4 & 4294967295L)) & 4294967295L);
                iArrA[i2] = (int) (4294967295L & j);
                iArrA[i3] = ((int) (((i4 & 4294967295L) * (i & 4294967295L)) >>> 32)) + ((int) (j >>> 32));
                if (i3 >= length) {
                    break;
                }
                i2 = i3;
            }
        }
        return g(iArrA);
    }
}

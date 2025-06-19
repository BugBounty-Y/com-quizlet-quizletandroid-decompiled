package androidx.navigation;

import android.os.Bundle;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3335e2;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3339f2;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3343g2;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import kotlin.collections.C4929u;
import kotlin.collections.C4930v;
import kotlin.collections.C4933y;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.navigation.e, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1283e extends AbstractC1285g {
    public final /* synthetic */ int q;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C1283e(boolean z, int i) {
        super(z);
        this.q = i;
    }

    public static float[] j(String value) {
        Intrinsics.checkNotNullParameter(value, "value");
        return new float[]{((Number) S.h.d(value)).floatValue()};
    }

    public static int[] k(String value) {
        Intrinsics.checkNotNullParameter(value, "value");
        return new int[]{((Number) S.b.d(value)).intValue()};
    }

    public static long[] l(String value) {
        Intrinsics.checkNotNullParameter(value, "value");
        return new long[]{((Number) S.e.d(value)).longValue()};
    }

    public static boolean[] m(String value) {
        Intrinsics.checkNotNullParameter(value, "value");
        return new boolean[]{((Boolean) S.k.d(value)).booleanValue()};
    }

    @Override // androidx.navigation.S
    public final Object a(Bundle source, String key) {
        switch (this.q) {
            case 0:
                Intrinsics.checkNotNullParameter(source, "bundle");
                Intrinsics.checkNotNullParameter(key, "key");
                Intrinsics.checkNotNullParameter(source, "source");
                if (!AbstractC3335e2.a(source, key) || AbstractC3335e2.k(source, key)) {
                    return null;
                }
                Intrinsics.checkNotNullParameter(key, "key");
                boolean[] booleanArray = source.getBooleanArray(key);
                if (booleanArray != null) {
                    return booleanArray;
                }
                AbstractC3339f2.h(key);
                throw null;
            case 1:
                Intrinsics.checkNotNullParameter(source, "bundle");
                Intrinsics.checkNotNullParameter(key, "key");
                Intrinsics.checkNotNullParameter(source, "source");
                if (!AbstractC3335e2.a(source, key) || AbstractC3335e2.k(source, key)) {
                    return null;
                }
                Intrinsics.checkNotNullParameter(key, "key");
                boolean[] booleanArray2 = source.getBooleanArray(key);
                if (booleanArray2 != null) {
                    return C4933y.Q(booleanArray2);
                }
                AbstractC3339f2.h(key);
                throw null;
            case 2:
                Intrinsics.checkNotNullParameter(source, "bundle");
                Intrinsics.checkNotNullParameter(key, "key");
                Intrinsics.checkNotNullParameter(source, "source");
                if (!AbstractC3335e2.a(source, key) || AbstractC3335e2.k(source, key)) {
                    return null;
                }
                Intrinsics.checkNotNullParameter(key, "key");
                float[] floatArray = source.getFloatArray(key);
                if (floatArray != null) {
                    return floatArray;
                }
                AbstractC3339f2.h(key);
                throw null;
            case 3:
                Intrinsics.checkNotNullParameter(source, "bundle");
                Intrinsics.checkNotNullParameter(key, "key");
                Intrinsics.checkNotNullParameter(source, "source");
                if (!AbstractC3335e2.a(source, key) || AbstractC3335e2.k(source, key)) {
                    return null;
                }
                Intrinsics.checkNotNullParameter(key, "key");
                float[] floatArray2 = source.getFloatArray(key);
                if (floatArray2 != null) {
                    return C4933y.N(floatArray2);
                }
                AbstractC3339f2.h(key);
                throw null;
            case 4:
                Intrinsics.checkNotNullParameter(source, "bundle");
                Intrinsics.checkNotNullParameter(key, "key");
                Intrinsics.checkNotNullParameter(source, "source");
                if (!AbstractC3335e2.a(source, key) || AbstractC3335e2.k(source, key)) {
                    return null;
                }
                Intrinsics.checkNotNullParameter(key, "key");
                int[] intArray = source.getIntArray(key);
                if (intArray != null) {
                    return intArray;
                }
                AbstractC3339f2.h(key);
                throw null;
            case 5:
                Intrinsics.checkNotNullParameter(source, "bundle");
                Intrinsics.checkNotNullParameter(key, "key");
                Intrinsics.checkNotNullParameter(source, "source");
                if (!AbstractC3335e2.a(source, key) || AbstractC3335e2.k(source, key)) {
                    return null;
                }
                Intrinsics.checkNotNullParameter(key, "key");
                int[] intArray2 = source.getIntArray(key);
                if (intArray2 == null) {
                    AbstractC3339f2.h(key);
                    throw null;
                }
                Intrinsics.checkNotNullParameter(intArray2, "<this>");
                int length = intArray2.length;
                return length != 0 ? length != 1 ? C4933y.R(intArray2) : kotlin.collections.A.b(Integer.valueOf(intArray2[0])) : kotlin.collections.K.a;
            case 6:
                Intrinsics.checkNotNullParameter(source, "bundle");
                Intrinsics.checkNotNullParameter(key, "key");
                Intrinsics.checkNotNullParameter(source, "source");
                if (!AbstractC3335e2.a(source, key) || AbstractC3335e2.k(source, key)) {
                    return null;
                }
                Intrinsics.checkNotNullParameter(key, "key");
                long[] longArray = source.getLongArray(key);
                if (longArray != null) {
                    return longArray;
                }
                AbstractC3339f2.h(key);
                throw null;
            case 7:
                Intrinsics.checkNotNullParameter(source, "bundle");
                Intrinsics.checkNotNullParameter(key, "key");
                Intrinsics.checkNotNullParameter(source, "source");
                if (!AbstractC3335e2.a(source, key) || AbstractC3335e2.k(source, key)) {
                    return null;
                }
                Intrinsics.checkNotNullParameter(key, "key");
                long[] longArray2 = source.getLongArray(key);
                if (longArray2 != null) {
                    return C4933y.O(longArray2);
                }
                AbstractC3339f2.h(key);
                throw null;
            case 8:
                Intrinsics.checkNotNullParameter(source, "bundle");
                Intrinsics.checkNotNullParameter(key, "key");
                Intrinsics.checkNotNullParameter(source, "source");
                if (!AbstractC3335e2.a(source, key) || AbstractC3335e2.k(source, key)) {
                    return null;
                }
                return AbstractC3335e2.j(source, key);
            default:
                Intrinsics.checkNotNullParameter(source, "bundle");
                Intrinsics.checkNotNullParameter(key, "key");
                Intrinsics.checkNotNullParameter(source, "source");
                if (!AbstractC3335e2.a(source, key) || AbstractC3335e2.k(source, key)) {
                    return null;
                }
                return C4933y.P(AbstractC3335e2.j(source, key));
        }
    }

    @Override // androidx.navigation.S
    public final String b() {
        switch (this.q) {
            case 0:
                return "boolean[]";
            case 1:
                return "List<Boolean>";
            case 2:
                return "float[]";
            case 3:
                return "List<Float>";
            case 4:
                return "integer[]";
            case 5:
                return "List<Int>";
            case 6:
                return "long[]";
            case 7:
                return "List<Long>";
            case 8:
                return "string[]";
            default:
                return "List<String>";
        }
    }

    @Override // androidx.navigation.S
    public final Object c(Object obj, String value) {
        switch (this.q) {
            case 0:
                boolean[] zArr = (boolean[]) obj;
                Intrinsics.checkNotNullParameter(value, "value");
                if (zArr == null) {
                    return m(value);
                }
                boolean[] elements = m(value);
                Intrinsics.checkNotNullParameter(zArr, "<this>");
                Intrinsics.checkNotNullParameter(elements, "elements");
                int length = zArr.length;
                boolean[] zArrCopyOf = Arrays.copyOf(zArr, length + 1);
                System.arraycopy(elements, 0, zArrCopyOf, length, 1);
                Intrinsics.d(zArrCopyOf);
                return zArrCopyOf;
            case 1:
                List list = (List) obj;
                Intrinsics.checkNotNullParameter(value, "value");
                C1284f c1284f = S.k;
                if (list != null) {
                    Intrinsics.checkNotNullParameter(value, "value");
                    return CollectionsKt.c0(list, kotlin.collections.A.b(c1284f.d(value)));
                }
                Intrinsics.checkNotNullParameter(value, "value");
                return kotlin.collections.A.b(c1284f.d(value));
            case 2:
                float[] fArr = (float[]) obj;
                Intrinsics.checkNotNullParameter(value, "value");
                if (fArr == null) {
                    return j(value);
                }
                float[] elements2 = j(value);
                Intrinsics.checkNotNullParameter(fArr, "<this>");
                Intrinsics.checkNotNullParameter(elements2, "elements");
                int length2 = fArr.length;
                float[] fArrCopyOf = Arrays.copyOf(fArr, length2 + 1);
                System.arraycopy(elements2, 0, fArrCopyOf, length2, 1);
                Intrinsics.d(fArrCopyOf);
                return fArrCopyOf;
            case 3:
                List list2 = (List) obj;
                Intrinsics.checkNotNullParameter(value, "value");
                C1284f c1284f2 = S.h;
                if (list2 != null) {
                    Intrinsics.checkNotNullParameter(value, "value");
                    return CollectionsKt.c0(list2, kotlin.collections.A.b(c1284f2.d(value)));
                }
                Intrinsics.checkNotNullParameter(value, "value");
                return kotlin.collections.A.b(c1284f2.d(value));
            case 4:
                int[] iArr = (int[]) obj;
                Intrinsics.checkNotNullParameter(value, "value");
                if (iArr == null) {
                    return k(value);
                }
                int[] elements3 = k(value);
                Intrinsics.checkNotNullParameter(iArr, "<this>");
                Intrinsics.checkNotNullParameter(elements3, "elements");
                int length3 = iArr.length;
                int[] iArrCopyOf = Arrays.copyOf(iArr, length3 + 1);
                System.arraycopy(elements3, 0, iArrCopyOf, length3, 1);
                Intrinsics.d(iArrCopyOf);
                return iArrCopyOf;
            case 5:
                List list3 = (List) obj;
                Intrinsics.checkNotNullParameter(value, "value");
                C1284f c1284f3 = S.b;
                if (list3 != null) {
                    Intrinsics.checkNotNullParameter(value, "value");
                    return CollectionsKt.c0(list3, kotlin.collections.A.b(c1284f3.d(value)));
                }
                Intrinsics.checkNotNullParameter(value, "value");
                return kotlin.collections.A.b(c1284f3.d(value));
            case 6:
                long[] jArr = (long[]) obj;
                Intrinsics.checkNotNullParameter(value, "value");
                if (jArr == null) {
                    return l(value);
                }
                long[] elements4 = l(value);
                Intrinsics.checkNotNullParameter(jArr, "<this>");
                Intrinsics.checkNotNullParameter(elements4, "elements");
                int length4 = jArr.length;
                long[] jArrCopyOf = Arrays.copyOf(jArr, length4 + 1);
                System.arraycopy(elements4, 0, jArrCopyOf, length4, 1);
                Intrinsics.d(jArrCopyOf);
                return jArrCopyOf;
            case 7:
                List list4 = (List) obj;
                Intrinsics.checkNotNullParameter(value, "value");
                C1284f c1284f4 = S.e;
                if (list4 != null) {
                    Intrinsics.checkNotNullParameter(value, "value");
                    return CollectionsKt.c0(list4, kotlin.collections.A.b(c1284f4.d(value)));
                }
                Intrinsics.checkNotNullParameter(value, "value");
                return kotlin.collections.A.b(c1284f4.d(value));
            case 8:
                String[] strArr = (String[]) obj;
                Intrinsics.checkNotNullParameter(value, "value");
                if (strArr != null) {
                    Intrinsics.checkNotNullParameter(value, "value");
                    return (String[]) C4930v.s(strArr, new String[]{value});
                }
                Intrinsics.checkNotNullParameter(value, "value");
                return new String[]{value};
            default:
                List list5 = (List) obj;
                Intrinsics.checkNotNullParameter(value, "value");
                if (list5 != null) {
                    Intrinsics.checkNotNullParameter(value, "value");
                    return CollectionsKt.c0(list5, kotlin.collections.A.b(value));
                }
                Intrinsics.checkNotNullParameter(value, "value");
                return kotlin.collections.A.b(value);
        }
    }

    @Override // androidx.navigation.S
    public final Object d(String value) {
        switch (this.q) {
            case 0:
                return m(value);
            case 1:
                Intrinsics.checkNotNullParameter(value, "value");
                return kotlin.collections.A.b(S.k.d(value));
            case 2:
                return j(value);
            case 3:
                Intrinsics.checkNotNullParameter(value, "value");
                return kotlin.collections.A.b(S.h.d(value));
            case 4:
                return k(value);
            case 5:
                Intrinsics.checkNotNullParameter(value, "value");
                return kotlin.collections.A.b(S.b.d(value));
            case 6:
                return l(value);
            case 7:
                Intrinsics.checkNotNullParameter(value, "value");
                return kotlin.collections.A.b(S.e.d(value));
            case 8:
                Intrinsics.checkNotNullParameter(value, "value");
                return new String[]{value};
            default:
                Intrinsics.checkNotNullParameter(value, "value");
                return kotlin.collections.A.b(value);
        }
    }

    @Override // androidx.navigation.S
    public final void e(Bundle source, String key, Object obj) {
        switch (this.q) {
            case 0:
                boolean[] value = (boolean[]) obj;
                Intrinsics.checkNotNullParameter(source, "bundle");
                Intrinsics.checkNotNullParameter(key, "key");
                Intrinsics.checkNotNullParameter(source, "source");
                if (value == null) {
                    AbstractC3343g2.e(source, key);
                    break;
                } else {
                    Intrinsics.checkNotNullParameter(key, "key");
                    Intrinsics.checkNotNullParameter(value, "value");
                    source.putBooleanArray(key, value);
                    break;
                }
            case 1:
                List list = (List) obj;
                Intrinsics.checkNotNullParameter(source, "bundle");
                Intrinsics.checkNotNullParameter(key, "key");
                Intrinsics.checkNotNullParameter(source, "source");
                if (list == null) {
                    AbstractC3343g2.e(source, key);
                    break;
                } else {
                    boolean[] value2 = CollectionsKt.r0(list);
                    Intrinsics.checkNotNullParameter(key, "key");
                    Intrinsics.checkNotNullParameter(value2, "value");
                    source.putBooleanArray(key, value2);
                    break;
                }
            case 2:
                float[] value3 = (float[]) obj;
                Intrinsics.checkNotNullParameter(source, "bundle");
                Intrinsics.checkNotNullParameter(key, "key");
                Intrinsics.checkNotNullParameter(source, "source");
                if (value3 == null) {
                    AbstractC3343g2.e(source, key);
                    break;
                } else {
                    Intrinsics.checkNotNullParameter(key, "key");
                    Intrinsics.checkNotNullParameter(value3, "value");
                    source.putFloatArray(key, value3);
                    break;
                }
            case 3:
                List list2 = (List) obj;
                Intrinsics.checkNotNullParameter(source, "bundle");
                Intrinsics.checkNotNullParameter(key, "key");
                Intrinsics.checkNotNullParameter(source, "source");
                if (list2 == null) {
                    AbstractC3343g2.e(source, key);
                    break;
                } else {
                    float[] value4 = CollectionsKt.t0(list2);
                    Intrinsics.checkNotNullParameter(key, "key");
                    Intrinsics.checkNotNullParameter(value4, "value");
                    source.putFloatArray(key, value4);
                    break;
                }
            case 4:
                int[] value5 = (int[]) obj;
                Intrinsics.checkNotNullParameter(source, "bundle");
                Intrinsics.checkNotNullParameter(key, "key");
                Intrinsics.checkNotNullParameter(source, "source");
                if (value5 == null) {
                    AbstractC3343g2.e(source, key);
                    break;
                } else {
                    Intrinsics.checkNotNullParameter(key, "key");
                    Intrinsics.checkNotNullParameter(value5, "value");
                    source.putIntArray(key, value5);
                    break;
                }
            case 5:
                List list3 = (List) obj;
                Intrinsics.checkNotNullParameter(source, "bundle");
                Intrinsics.checkNotNullParameter(key, "key");
                if (list3 != null) {
                    Intrinsics.checkNotNullParameter(source, "source");
                    int[] value6 = CollectionsKt.v0(list3);
                    Intrinsics.checkNotNullParameter(key, "key");
                    Intrinsics.checkNotNullParameter(value6, "value");
                    source.putIntArray(key, value6);
                    break;
                }
                break;
            case 6:
                long[] value7 = (long[]) obj;
                Intrinsics.checkNotNullParameter(source, "bundle");
                Intrinsics.checkNotNullParameter(key, "key");
                Intrinsics.checkNotNullParameter(source, "source");
                if (value7 == null) {
                    AbstractC3343g2.e(source, key);
                    break;
                } else {
                    Intrinsics.checkNotNullParameter(key, "key");
                    Intrinsics.checkNotNullParameter(value7, "value");
                    source.putLongArray(key, value7);
                    break;
                }
            case 7:
                List list4 = (List) obj;
                Intrinsics.checkNotNullParameter(source, "bundle");
                Intrinsics.checkNotNullParameter(key, "key");
                Intrinsics.checkNotNullParameter(source, "source");
                if (list4 == null) {
                    AbstractC3343g2.e(source, key);
                    break;
                } else {
                    long[] value8 = CollectionsKt.x0(list4);
                    Intrinsics.checkNotNullParameter(key, "key");
                    Intrinsics.checkNotNullParameter(value8, "value");
                    source.putLongArray(key, value8);
                    break;
                }
            case 8:
                String[] strArr = (String[]) obj;
                Intrinsics.checkNotNullParameter(source, "bundle");
                Intrinsics.checkNotNullParameter(key, "key");
                Intrinsics.checkNotNullParameter(source, "source");
                if (strArr == null) {
                    AbstractC3343g2.e(source, key);
                    break;
                } else {
                    AbstractC3343g2.i(source, key, strArr);
                    break;
                }
            default:
                List list5 = (List) obj;
                Intrinsics.checkNotNullParameter(source, "bundle");
                Intrinsics.checkNotNullParameter(key, "key");
                Intrinsics.checkNotNullParameter(source, "source");
                if (list5 == null) {
                    AbstractC3343g2.e(source, key);
                    break;
                } else {
                    AbstractC3343g2.i(source, key, (String[]) list5.toArray(new String[0]));
                    break;
                }
        }
    }

    @Override // androidx.navigation.S
    public final boolean g(Object obj, Object obj2) {
        Boolean[] boolArr;
        Float[] fArr;
        Integer[] numArr;
        Long[] lArr;
        switch (this.q) {
            case 0:
                boolean[] zArr = (boolean[]) obj;
                boolean[] zArr2 = (boolean[]) obj2;
                Boolean[] boolArr2 = null;
                if (zArr != null) {
                    Intrinsics.checkNotNullParameter(zArr, "<this>");
                    boolArr = new Boolean[zArr.length];
                    int length = zArr.length;
                    for (int i = 0; i < length; i++) {
                        boolArr[i] = Boolean.valueOf(zArr[i]);
                    }
                } else {
                    boolArr = null;
                }
                if (zArr2 != null) {
                    Intrinsics.checkNotNullParameter(zArr2, "<this>");
                    boolArr2 = new Boolean[zArr2.length];
                    int length2 = zArr2.length;
                    for (int i2 = 0; i2 < length2; i2++) {
                        boolArr2[i2] = Boolean.valueOf(zArr2[i2]);
                    }
                }
                return C4929u.b(boolArr, boolArr2);
            case 1:
                List list = (List) obj;
                List list2 = (List) obj2;
                return C4929u.b(list != null ? (Boolean[]) list.toArray(new Boolean[0]) : null, list2 != null ? (Boolean[]) list2.toArray(new Boolean[0]) : null);
            case 2:
                float[] fArr2 = (float[]) obj;
                float[] fArr3 = (float[]) obj2;
                Float[] fArr4 = null;
                if (fArr2 != null) {
                    Intrinsics.checkNotNullParameter(fArr2, "<this>");
                    fArr = new Float[fArr2.length];
                    int length3 = fArr2.length;
                    for (int i3 = 0; i3 < length3; i3++) {
                        fArr[i3] = Float.valueOf(fArr2[i3]);
                    }
                } else {
                    fArr = null;
                }
                if (fArr3 != null) {
                    Intrinsics.checkNotNullParameter(fArr3, "<this>");
                    fArr4 = new Float[fArr3.length];
                    int length4 = fArr3.length;
                    for (int i4 = 0; i4 < length4; i4++) {
                        fArr4[i4] = Float.valueOf(fArr3[i4]);
                    }
                }
                return C4929u.b(fArr, fArr4);
            case 3:
                List list3 = (List) obj;
                List list4 = (List) obj2;
                return C4929u.b(list3 != null ? (Float[]) list3.toArray(new Float[0]) : null, list4 != null ? (Float[]) list4.toArray(new Float[0]) : null);
            case 4:
                int[] iArr = (int[]) obj;
                int[] iArr2 = (int[]) obj2;
                Integer[] numArr2 = null;
                if (iArr != null) {
                    Intrinsics.checkNotNullParameter(iArr, "<this>");
                    numArr = new Integer[iArr.length];
                    int length5 = iArr.length;
                    for (int i5 = 0; i5 < length5; i5++) {
                        numArr[i5] = Integer.valueOf(iArr[i5]);
                    }
                } else {
                    numArr = null;
                }
                if (iArr2 != null) {
                    Intrinsics.checkNotNullParameter(iArr2, "<this>");
                    numArr2 = new Integer[iArr2.length];
                    int length6 = iArr2.length;
                    for (int i6 = 0; i6 < length6; i6++) {
                        numArr2[i6] = Integer.valueOf(iArr2[i6]);
                    }
                }
                return C4929u.b(numArr, numArr2);
            case 5:
                List list5 = (List) obj;
                List list6 = (List) obj2;
                return C4929u.b(list5 != null ? (Integer[]) list5.toArray(new Integer[0]) : null, list6 != null ? (Integer[]) list6.toArray(new Integer[0]) : null);
            case 6:
                long[] jArr = (long[]) obj;
                long[] jArr2 = (long[]) obj2;
                Long[] lArr2 = null;
                if (jArr != null) {
                    Intrinsics.checkNotNullParameter(jArr, "<this>");
                    lArr = new Long[jArr.length];
                    int length7 = jArr.length;
                    for (int i7 = 0; i7 < length7; i7++) {
                        lArr[i7] = Long.valueOf(jArr[i7]);
                    }
                } else {
                    lArr = null;
                }
                if (jArr2 != null) {
                    Intrinsics.checkNotNullParameter(jArr2, "<this>");
                    lArr2 = new Long[jArr2.length];
                    int length8 = jArr2.length;
                    for (int i8 = 0; i8 < length8; i8++) {
                        lArr2[i8] = Long.valueOf(jArr2[i8]);
                    }
                }
                return C4929u.b(lArr, lArr2);
            case 7:
                List list7 = (List) obj;
                List list8 = (List) obj2;
                return C4929u.b(list7 != null ? (Long[]) list7.toArray(new Long[0]) : null, list8 != null ? (Long[]) list8.toArray(new Long[0]) : null);
            case 8:
                return C4929u.b((String[]) obj, (String[]) obj2);
            default:
                List list9 = (List) obj;
                List list10 = (List) obj2;
                return C4929u.b(list9 != null ? (String[]) list9.toArray(new String[0]) : null, list10 != null ? (String[]) list10.toArray(new String[0]) : null);
        }
    }

    @Override // androidx.navigation.AbstractC1285g
    public final Object h() {
        switch (this.q) {
            case 0:
                return new boolean[0];
            case 1:
                return kotlin.collections.K.a;
            case 2:
                return new float[0];
            case 3:
                return kotlin.collections.K.a;
            case 4:
                return new int[0];
            case 5:
                return kotlin.collections.K.a;
            case 6:
                return new long[0];
            case 7:
                return kotlin.collections.K.a;
            case 8:
                return new String[0];
            default:
                return kotlin.collections.K.a;
        }
    }

    @Override // androidx.navigation.AbstractC1285g
    public final List i(Object obj) {
        List listQ;
        List listN;
        List listO;
        switch (this.q) {
            case 0:
                boolean[] zArr = (boolean[]) obj;
                if (zArr != null && (listQ = C4933y.Q(zArr)) != null) {
                    ArrayList arrayList = new ArrayList(kotlin.collections.C.q(listQ, 10));
                    Iterator it2 = listQ.iterator();
                    while (it2.hasNext()) {
                        arrayList.add(String.valueOf(((Boolean) it2.next()).booleanValue()));
                    }
                    break;
                } else {
                    break;
                }
                break;
            case 1:
                List list = (List) obj;
                if (list != null) {
                    ArrayList arrayList2 = new ArrayList(kotlin.collections.C.q(list, 10));
                    Iterator it3 = list.iterator();
                    while (it3.hasNext()) {
                        arrayList2.add(String.valueOf(((Boolean) it3.next()).booleanValue()));
                    }
                    break;
                } else {
                    break;
                }
            case 2:
                float[] fArr = (float[]) obj;
                if (fArr != null && (listN = C4933y.N(fArr)) != null) {
                    ArrayList arrayList3 = new ArrayList(kotlin.collections.C.q(listN, 10));
                    Iterator it4 = listN.iterator();
                    while (it4.hasNext()) {
                        arrayList3.add(String.valueOf(((Number) it4.next()).floatValue()));
                    }
                    break;
                } else {
                    break;
                }
                break;
            case 3:
                List list2 = (List) obj;
                if (list2 != null) {
                    ArrayList arrayList4 = new ArrayList(kotlin.collections.C.q(list2, 10));
                    Iterator it5 = list2.iterator();
                    while (it5.hasNext()) {
                        arrayList4.add(String.valueOf(((Number) it5.next()).floatValue()));
                    }
                    break;
                } else {
                    break;
                }
            case 4:
                int[] iArr = (int[]) obj;
                if (iArr != null) {
                    Intrinsics.checkNotNullParameter(iArr, "<this>");
                    int length = iArr.length;
                    Iterable iterableR = length != 0 ? length != 1 ? C4933y.R(iArr) : kotlin.collections.A.b(Integer.valueOf(iArr[0])) : kotlin.collections.K.a;
                    if (iterableR != null) {
                        ArrayList arrayList5 = new ArrayList(kotlin.collections.C.q(iterableR, 10));
                        Iterator it6 = iterableR.iterator();
                        while (it6.hasNext()) {
                            arrayList5.add(String.valueOf(((Number) it6.next()).intValue()));
                        }
                        break;
                    }
                }
                break;
            case 5:
                List list3 = (List) obj;
                if (list3 != null) {
                    ArrayList arrayList6 = new ArrayList(kotlin.collections.C.q(list3, 10));
                    Iterator it7 = list3.iterator();
                    while (it7.hasNext()) {
                        arrayList6.add(String.valueOf(((Number) it7.next()).intValue()));
                    }
                    break;
                } else {
                    break;
                }
            case 6:
                long[] jArr = (long[]) obj;
                if (jArr != null && (listO = C4933y.O(jArr)) != null) {
                    ArrayList arrayList7 = new ArrayList(kotlin.collections.C.q(listO, 10));
                    Iterator it8 = listO.iterator();
                    while (it8.hasNext()) {
                        arrayList7.add(String.valueOf(((Number) it8.next()).longValue()));
                    }
                    break;
                } else {
                    break;
                }
            case 7:
                List list4 = (List) obj;
                if (list4 != null) {
                    ArrayList arrayList8 = new ArrayList(kotlin.collections.C.q(list4, 10));
                    Iterator it9 = list4.iterator();
                    while (it9.hasNext()) {
                        arrayList8.add(String.valueOf(((Number) it9.next()).longValue()));
                    }
                    break;
                } else {
                    break;
                }
            case 8:
                String[] strArr = (String[]) obj;
                if (strArr != null) {
                    ArrayList arrayList9 = new ArrayList(strArr.length);
                    for (String str : strArr) {
                        arrayList9.add(T.b(str));
                    }
                    break;
                } else {
                    break;
                }
            default:
                List list5 = (List) obj;
                if (list5 != null) {
                    ArrayList arrayList10 = new ArrayList(kotlin.collections.C.q(list5, 10));
                    Iterator it10 = list5.iterator();
                    while (it10.hasNext()) {
                        arrayList10.add(T.b((String) it10.next()));
                    }
                    break;
                } else {
                    break;
                }
        }
        return kotlin.collections.K.a;
    }
}

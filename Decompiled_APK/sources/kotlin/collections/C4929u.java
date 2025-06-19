package kotlin.collections;

import java.util.Arrays;

/* renamed from: kotlin.collections.u, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public class C4929u extends C4928t {
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r5v2, types: [long[]] */
    /* JADX WARN: Type inference failed for: r5v4, types: [int[]] */
    /* JADX WARN: Type inference failed for: r5v6, types: [short[]] */
    public static boolean b(Object[] objArr, Object[] objArr2) {
        if (objArr == objArr2) {
            return true;
        }
        if (objArr == null || objArr2 == null || objArr.length != objArr2.length) {
            return false;
        }
        int length = objArr.length;
        for (int i = 0; i < length; i++) {
            Object obj = objArr[i];
            Object obj2 = objArr2[i];
            if (obj != obj2) {
                if (obj == null || obj2 == null) {
                    return false;
                }
                if ((obj instanceof Object[]) && (obj2 instanceof Object[])) {
                    if (!b((Object[]) obj, (Object[]) obj2)) {
                        return false;
                    }
                } else if ((obj instanceof byte[]) && (obj2 instanceof byte[])) {
                    if (!Arrays.equals((byte[]) obj, (byte[]) obj2)) {
                        return false;
                    }
                } else if ((obj instanceof short[]) && (obj2 instanceof short[])) {
                    if (!Arrays.equals((short[]) obj, (short[]) obj2)) {
                        return false;
                    }
                } else if ((obj instanceof int[]) && (obj2 instanceof int[])) {
                    if (!Arrays.equals((int[]) obj, (int[]) obj2)) {
                        return false;
                    }
                } else if ((obj instanceof long[]) && (obj2 instanceof long[])) {
                    if (!Arrays.equals((long[]) obj, (long[]) obj2)) {
                        return false;
                    }
                } else if ((obj instanceof float[]) && (obj2 instanceof float[])) {
                    if (!Arrays.equals((float[]) obj, (float[]) obj2)) {
                        return false;
                    }
                } else if ((obj instanceof double[]) && (obj2 instanceof double[])) {
                    if (!Arrays.equals((double[]) obj, (double[]) obj2)) {
                        return false;
                    }
                } else if ((obj instanceof char[]) && (obj2 instanceof char[])) {
                    if (!Arrays.equals((char[]) obj, (char[]) obj2)) {
                        return false;
                    }
                } else if ((obj instanceof boolean[]) && (obj2 instanceof boolean[])) {
                    if (!Arrays.equals((boolean[]) obj, (boolean[]) obj2)) {
                        return false;
                    }
                } else if ((obj instanceof kotlin.y) && (obj2 instanceof kotlin.y)) {
                    kotlin.y yVar = (kotlin.y) obj2;
                    byte[] bArr = ((kotlin.y) obj).a;
                    if (bArr == null) {
                        bArr = null;
                    }
                    byte[] bArr2 = yVar.a;
                    if (!Arrays.equals(bArr, bArr2 != null ? bArr2 : null)) {
                        return false;
                    }
                } else if ((obj instanceof kotlin.I) && (obj2 instanceof kotlin.I)) {
                    kotlin.I i2 = (kotlin.I) obj2;
                    short[] sArr = ((kotlin.I) obj).a;
                    if (sArr == null) {
                        sArr = null;
                    }
                    ?? r5 = i2.a;
                    if (!Arrays.equals(sArr, (short[]) (r5 != 0 ? r5 : null))) {
                        return false;
                    }
                } else if ((obj instanceof kotlin.B) && (obj2 instanceof kotlin.B)) {
                    kotlin.B b = (kotlin.B) obj2;
                    int[] iArr = ((kotlin.B) obj).a;
                    if (iArr == null) {
                        iArr = null;
                    }
                    ?? r52 = b.a;
                    if (!Arrays.equals(iArr, (int[]) (r52 != 0 ? r52 : null))) {
                        return false;
                    }
                } else if ((obj instanceof kotlin.E) && (obj2 instanceof kotlin.E)) {
                    kotlin.E e = (kotlin.E) obj2;
                    long[] jArr = ((kotlin.E) obj).a;
                    if (jArr == null) {
                        jArr = null;
                    }
                    ?? r53 = e.a;
                    if (!Arrays.equals(jArr, (long[]) (r53 != 0 ? r53 : null))) {
                        return false;
                    }
                } else if (!obj.equals(obj2)) {
                    return false;
                }
            }
        }
        return true;
    }
}

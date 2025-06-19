package androidx.navigation.serialization;

import android.os.Bundle;
import androidx.navigation.AbstractC1285g;
import androidx.navigation.C1284f;
import androidx.navigation.S;
import androidx.navigation.T;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3335e2;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3339f2;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3343g2;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import kotlin.collections.A;
import kotlin.collections.C;
import kotlin.collections.C4929u;
import kotlin.collections.C4930v;
import kotlin.collections.C4933y;
import kotlin.collections.CollectionsKt;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class c extends AbstractC1285g {
    public final /* synthetic */ int q;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ c(boolean z, int i) {
        super(z);
        this.q = i;
    }

    public static double[] j(String value) {
        Intrinsics.checkNotNullParameter(value, "value");
        Intrinsics.checkNotNullParameter(value, "value");
        return new double[]{Double.parseDouble(value)};
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
                double[] doubleArray = source.getDoubleArray(key);
                if (doubleArray != null) {
                    return doubleArray;
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
                double[] doubleArray2 = source.getDoubleArray(key);
                if (doubleArray2 != null) {
                    return C4933y.M(doubleArray2);
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
                String[] strArrJ = AbstractC3335e2.j(source, key);
                ArrayList arrayList = new ArrayList(strArrJ.length);
                for (String str : strArrJ) {
                    arrayList.add((String) S.n.d(str));
                }
                return (String[]) arrayList.toArray(new String[0]);
            default:
                Intrinsics.checkNotNullParameter(source, "bundle");
                Intrinsics.checkNotNullParameter(key, "key");
                Intrinsics.checkNotNullParameter(source, "source");
                if (!AbstractC3335e2.a(source, key) || AbstractC3335e2.k(source, key)) {
                    return null;
                }
                List listP = C4933y.P(AbstractC3335e2.j(source, key));
                ArrayList arrayList2 = new ArrayList(C.q(listP, 10));
                Iterator it2 = listP.iterator();
                while (it2.hasNext()) {
                    arrayList2.add((String) S.n.d((String) it2.next()));
                }
                return arrayList2;
        }
    }

    @Override // androidx.navigation.S
    public final String b() {
        switch (this.q) {
            case 0:
                return "double[]";
            case 1:
                return "List<Double>";
            case 2:
                return "string_nullable[]";
            default:
                return "List<String?>";
        }
    }

    @Override // androidx.navigation.S
    public final Object c(Object obj, String value) {
        switch (this.q) {
            case 0:
                double[] dArr = (double[]) obj;
                Intrinsics.checkNotNullParameter(value, "value");
                if (dArr == null) {
                    return j(value);
                }
                double[] elements = j(value);
                Intrinsics.checkNotNullParameter(dArr, "<this>");
                Intrinsics.checkNotNullParameter(elements, "elements");
                int length = dArr.length;
                double[] dArrCopyOf = Arrays.copyOf(dArr, length + 1);
                System.arraycopy(elements, 0, dArrCopyOf, length, 1);
                Intrinsics.d(dArrCopyOf);
                return dArrCopyOf;
            case 1:
                List list = (List) obj;
                Intrinsics.checkNotNullParameter(value, "value");
                if (list != null) {
                    Intrinsics.checkNotNullParameter(value, "value");
                    Intrinsics.checkNotNullParameter(value, "value");
                    return CollectionsKt.c0(list, A.b(Double.valueOf(Double.parseDouble(value))));
                }
                Intrinsics.checkNotNullParameter(value, "value");
                Intrinsics.checkNotNullParameter(value, "value");
                return A.b(Double.valueOf(Double.parseDouble(value)));
            case 2:
                String[] strArr = (String[]) obj;
                Intrinsics.checkNotNullParameter(value, "value");
                return strArr != null ? (String[]) C4930v.s(strArr, k(value)) : k(value);
            default:
                List list2 = (List) obj;
                Intrinsics.checkNotNullParameter(value, "value");
                C1284f c1284f = S.n;
                if (list2 != null) {
                    Intrinsics.checkNotNullParameter(value, "value");
                    return CollectionsKt.c0(list2, A.b(c1284f.d(value)));
                }
                Intrinsics.checkNotNullParameter(value, "value");
                return A.b(c1284f.d(value));
        }
    }

    @Override // androidx.navigation.S
    public final Object d(String value) {
        switch (this.q) {
            case 0:
                return j(value);
            case 1:
                Intrinsics.checkNotNullParameter(value, "value");
                Intrinsics.checkNotNullParameter(value, "value");
                return A.b(Double.valueOf(Double.parseDouble(value)));
            case 2:
                return k(value);
            default:
                Intrinsics.checkNotNullParameter(value, "value");
                return A.b(S.n.d(value));
        }
    }

    @Override // androidx.navigation.S
    public final void e(Bundle source, String key, Object obj) {
        switch (this.q) {
            case 0:
                double[] value = (double[]) obj;
                Intrinsics.checkNotNullParameter(source, "bundle");
                Intrinsics.checkNotNullParameter(key, "key");
                Intrinsics.checkNotNullParameter(source, "source");
                if (value == null) {
                    AbstractC3343g2.e(source, key);
                    break;
                } else {
                    Intrinsics.checkNotNullParameter(key, "key");
                    Intrinsics.checkNotNullParameter(value, "value");
                    source.putDoubleArray(key, value);
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
                    Intrinsics.checkNotNullParameter(list, "<this>");
                    double[] value2 = new double[list.size()];
                    Iterator it2 = list.iterator();
                    int i = 0;
                    while (it2.hasNext()) {
                        value2[i] = ((Number) it2.next()).doubleValue();
                        i++;
                    }
                    Intrinsics.checkNotNullParameter(key, "key");
                    Intrinsics.checkNotNullParameter(value2, "value");
                    source.putDoubleArray(key, value2);
                    break;
                }
            case 2:
                String[] strArr = (String[]) obj;
                Intrinsics.checkNotNullParameter(source, "bundle");
                Intrinsics.checkNotNullParameter(key, "key");
                Intrinsics.checkNotNullParameter(source, "source");
                if (strArr == null) {
                    AbstractC3343g2.e(source, key);
                    break;
                } else {
                    ArrayList arrayList = new ArrayList(strArr.length);
                    for (String str : strArr) {
                        if (str == null) {
                            str = "null";
                        }
                        arrayList.add(str);
                    }
                    AbstractC3343g2.i(source, key, (String[]) arrayList.toArray(new String[0]));
                    break;
                }
            default:
                List<String> list2 = (List) obj;
                Intrinsics.checkNotNullParameter(source, "bundle");
                Intrinsics.checkNotNullParameter(key, "key");
                Intrinsics.checkNotNullParameter(source, "source");
                if (list2 == null) {
                    AbstractC3343g2.e(source, key);
                    break;
                } else {
                    ArrayList arrayList2 = new ArrayList(C.q(list2, 10));
                    for (String str2 : list2) {
                        if (str2 == null) {
                            str2 = "null";
                        }
                        arrayList2.add(str2);
                    }
                    AbstractC3343g2.i(source, key, (String[]) arrayList2.toArray(new String[0]));
                    break;
                }
        }
    }

    @Override // androidx.navigation.S
    public final boolean g(Object obj, Object obj2) {
        Double[] dArr;
        switch (this.q) {
            case 0:
                double[] dArr2 = (double[]) obj;
                double[] dArr3 = (double[]) obj2;
                Double[] dArr4 = null;
                if (dArr2 != null) {
                    Intrinsics.checkNotNullParameter(dArr2, "<this>");
                    dArr = new Double[dArr2.length];
                    int length = dArr2.length;
                    for (int i = 0; i < length; i++) {
                        dArr[i] = Double.valueOf(dArr2[i]);
                    }
                } else {
                    dArr = null;
                }
                if (dArr3 != null) {
                    Intrinsics.checkNotNullParameter(dArr3, "<this>");
                    dArr4 = new Double[dArr3.length];
                    int length2 = dArr3.length;
                    for (int i2 = 0; i2 < length2; i2++) {
                        dArr4[i2] = Double.valueOf(dArr3[i2]);
                    }
                }
                return C4929u.b(dArr, dArr4);
            case 1:
                List list = (List) obj;
                List list2 = (List) obj2;
                return C4929u.b(list != null ? (Double[]) list.toArray(new Double[0]) : null, list2 != null ? (Double[]) list2.toArray(new Double[0]) : null);
            case 2:
                return C4929u.b((String[]) obj, (String[]) obj2);
            default:
                List list3 = (List) obj;
                List list4 = (List) obj2;
                return C4929u.b(list3 != null ? (String[]) list3.toArray(new String[0]) : null, list4 != null ? (String[]) list4.toArray(new String[0]) : null);
        }
    }

    @Override // androidx.navigation.AbstractC1285g
    public final Object h() {
        switch (this.q) {
            case 0:
                return new double[0];
            case 1:
                return K.a;
            case 2:
                return new String[0];
            default:
                return K.a;
        }
    }

    @Override // androidx.navigation.AbstractC1285g
    public final List i(Object obj) {
        List listM;
        String strB;
        String strB2;
        switch (this.q) {
            case 0:
                double[] dArr = (double[]) obj;
                if (dArr != null && (listM = C4933y.M(dArr)) != null) {
                    ArrayList arrayList = new ArrayList(C.q(listM, 10));
                    Iterator it2 = listM.iterator();
                    while (it2.hasNext()) {
                        arrayList.add(String.valueOf(((Number) it2.next()).doubleValue()));
                    }
                    break;
                } else {
                    break;
                }
                break;
            case 1:
                List list = (List) obj;
                if (list != null) {
                    ArrayList arrayList2 = new ArrayList(C.q(list, 10));
                    Iterator it3 = list.iterator();
                    while (it3.hasNext()) {
                        arrayList2.add(String.valueOf(((Number) it3.next()).doubleValue()));
                    }
                    break;
                } else {
                    break;
                }
            case 2:
                String[] strArr = (String[]) obj;
                if (strArr != null) {
                    ArrayList arrayList3 = new ArrayList(strArr.length);
                    for (String str : strArr) {
                        if (str == null || (strB = T.b(str)) == null) {
                            strB = "null";
                        }
                        arrayList3.add(strB);
                    }
                    break;
                } else {
                    break;
                }
                break;
            default:
                List<String> list2 = (List) obj;
                if (list2 != null) {
                    ArrayList arrayList4 = new ArrayList(C.q(list2, 10));
                    for (String str2 : list2) {
                        if (str2 == null || (strB2 = T.b(str2)) == null) {
                            strB2 = "null";
                        }
                        arrayList4.add(strB2);
                    }
                    break;
                } else {
                    break;
                }
                break;
        }
        return K.a;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public String[] k(String value) {
        Intrinsics.checkNotNullParameter(value, "value");
        return new String[]{S.n.d(value)};
    }
}

package androidx.work;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3390s2;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import kotlin.jvm.internal.C4950i;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class G {
    public static final F b = new F(1);
    public static final F c = new F(0);
    public Object a = new LinkedHashMap();

    public C1437k a() {
        C1437k c1437k = new C1437k((LinkedHashMap) this.a);
        AbstractC3390s2.d(c1437k);
        return c1437k;
    }

    public void b(Object obj, String key) {
        Object[] objArr;
        Intrinsics.checkNotNullParameter(key, "key");
        LinkedHashMap linkedHashMap = (LinkedHashMap) this.a;
        if (obj == null) {
            obj = null;
        } else {
            C4950i c4950iA = kotlin.jvm.internal.K.a(obj.getClass());
            if (!(c4950iA.equals(kotlin.jvm.internal.K.a(Boolean.TYPE)) ? true : c4950iA.equals(kotlin.jvm.internal.K.a(Byte.TYPE)) ? true : c4950iA.equals(kotlin.jvm.internal.K.a(Integer.TYPE)) ? true : c4950iA.equals(kotlin.jvm.internal.K.a(Long.TYPE)) ? true : c4950iA.equals(kotlin.jvm.internal.K.a(Float.TYPE)) ? true : c4950iA.equals(kotlin.jvm.internal.K.a(Double.TYPE)) ? true : c4950iA.equals(kotlin.jvm.internal.K.a(String.class)) ? true : c4950iA.equals(kotlin.jvm.internal.K.a(Boolean[].class)) ? true : c4950iA.equals(kotlin.jvm.internal.K.a(Byte[].class)) ? true : c4950iA.equals(kotlin.jvm.internal.K.a(Integer[].class)) ? true : c4950iA.equals(kotlin.jvm.internal.K.a(Long[].class)) ? true : c4950iA.equals(kotlin.jvm.internal.K.a(Float[].class)) ? true : c4950iA.equals(kotlin.jvm.internal.K.a(Double[].class)) ? true : c4950iA.equals(kotlin.jvm.internal.K.a(String[].class)))) {
                int i = 0;
                if (c4950iA.equals(kotlin.jvm.internal.K.a(boolean[].class))) {
                    boolean[] zArr = (boolean[]) obj;
                    String str = AbstractC1438l.a;
                    int length = zArr.length;
                    objArr = new Boolean[length];
                    while (i < length) {
                        objArr[i] = Boolean.valueOf(zArr[i]);
                        i++;
                    }
                } else if (c4950iA.equals(kotlin.jvm.internal.K.a(byte[].class))) {
                    byte[] bArr = (byte[]) obj;
                    String str2 = AbstractC1438l.a;
                    int length2 = bArr.length;
                    objArr = new Byte[length2];
                    while (i < length2) {
                        objArr[i] = Byte.valueOf(bArr[i]);
                        i++;
                    }
                } else if (c4950iA.equals(kotlin.jvm.internal.K.a(int[].class))) {
                    int[] iArr = (int[]) obj;
                    String str3 = AbstractC1438l.a;
                    int length3 = iArr.length;
                    objArr = new Integer[length3];
                    while (i < length3) {
                        objArr[i] = Integer.valueOf(iArr[i]);
                        i++;
                    }
                } else if (c4950iA.equals(kotlin.jvm.internal.K.a(long[].class))) {
                    long[] jArr = (long[]) obj;
                    String str4 = AbstractC1438l.a;
                    int length4 = jArr.length;
                    objArr = new Long[length4];
                    while (i < length4) {
                        objArr[i] = Long.valueOf(jArr[i]);
                        i++;
                    }
                } else if (c4950iA.equals(kotlin.jvm.internal.K.a(float[].class))) {
                    float[] fArr = (float[]) obj;
                    String str5 = AbstractC1438l.a;
                    int length5 = fArr.length;
                    objArr = new Float[length5];
                    while (i < length5) {
                        objArr[i] = Float.valueOf(fArr[i]);
                        i++;
                    }
                } else {
                    if (!c4950iA.equals(kotlin.jvm.internal.K.a(double[].class))) {
                        throw new IllegalArgumentException("Key " + key + " has invalid type " + c4950iA);
                    }
                    double[] dArr = (double[]) obj;
                    String str6 = AbstractC1438l.a;
                    int length6 = dArr.length;
                    objArr = new Double[length6];
                    while (i < length6) {
                        objArr[i] = Double.valueOf(dArr[i]);
                        i++;
                    }
                }
                obj = objArr;
            }
        }
        linkedHashMap.put(key, obj);
    }

    public void c(HashMap values) {
        Intrinsics.checkNotNullParameter(values, "values");
        for (Map.Entry entry : values.entrySet()) {
            b(entry.getValue(), (String) entry.getKey());
        }
    }
}

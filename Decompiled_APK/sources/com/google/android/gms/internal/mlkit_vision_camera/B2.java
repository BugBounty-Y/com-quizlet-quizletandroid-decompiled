package com.google.android.gms.internal.mlkit_vision_camera;

import android.net.Uri;
import android.os.Build;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.work.C1424e;
import androidx.work.EnumC1420a;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.util.HashMap;
import java.util.LinkedHashSet;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class B2 {
    public static final /* synthetic */ int a = 0;

    public static final LinkedHashSet a(byte[] bytes) throws IOException {
        Intrinsics.checkNotNullParameter(bytes, "bytes");
        LinkedHashSet linkedHashSet = new LinkedHashSet();
        if (bytes.length != 0) {
            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bytes);
            try {
                try {
                    ObjectInputStream objectInputStream = new ObjectInputStream(byteArrayInputStream);
                    try {
                        int i = objectInputStream.readInt();
                        for (int i2 = 0; i2 < i; i2++) {
                            Uri uri = Uri.parse(objectInputStream.readUTF());
                            boolean z = objectInputStream.readBoolean();
                            Intrinsics.checkNotNullExpressionValue(uri, "uri");
                            linkedHashSet.add(new C1424e(z, uri));
                        }
                        Unit unit = Unit.a;
                        objectInputStream.close();
                    } finally {
                    }
                } finally {
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
            Unit unit2 = Unit.a;
            byteArrayInputStream.close();
        }
        return linkedHashSet;
    }

    public static void b(StringBuilder sb, Object obj, HashMap map) {
        if (obj == null) {
            sb.append("null");
            return;
        }
        if (!obj.getClass().isArray()) {
            try {
                sb.append(obj.toString());
                return;
            } catch (Throwable th) {
                org.slf4j.helpers.g.a("Failed toString() invocation on an object of type [" + obj.getClass().getName() + "]", th);
                sb.append("[FAILED toString()]");
                return;
            }
        }
        int i = 0;
        if (obj instanceof boolean[]) {
            boolean[] zArr = (boolean[]) obj;
            sb.append('[');
            int length = zArr.length;
            while (i < length) {
                sb.append(zArr[i]);
                if (i != length - 1) {
                    sb.append(", ");
                }
                i++;
            }
            sb.append(']');
            return;
        }
        if (obj instanceof byte[]) {
            byte[] bArr = (byte[]) obj;
            sb.append('[');
            int length2 = bArr.length;
            while (i < length2) {
                sb.append((int) bArr[i]);
                if (i != length2 - 1) {
                    sb.append(", ");
                }
                i++;
            }
            sb.append(']');
            return;
        }
        if (obj instanceof char[]) {
            char[] cArr = (char[]) obj;
            sb.append('[');
            int length3 = cArr.length;
            while (i < length3) {
                sb.append(cArr[i]);
                if (i != length3 - 1) {
                    sb.append(", ");
                }
                i++;
            }
            sb.append(']');
            return;
        }
        if (obj instanceof short[]) {
            short[] sArr = (short[]) obj;
            sb.append('[');
            int length4 = sArr.length;
            while (i < length4) {
                sb.append((int) sArr[i]);
                if (i != length4 - 1) {
                    sb.append(", ");
                }
                i++;
            }
            sb.append(']');
            return;
        }
        if (obj instanceof int[]) {
            int[] iArr = (int[]) obj;
            sb.append('[');
            int length5 = iArr.length;
            while (i < length5) {
                sb.append(iArr[i]);
                if (i != length5 - 1) {
                    sb.append(", ");
                }
                i++;
            }
            sb.append(']');
            return;
        }
        if (obj instanceof long[]) {
            long[] jArr = (long[]) obj;
            sb.append('[');
            int length6 = jArr.length;
            while (i < length6) {
                sb.append(jArr[i]);
                if (i != length6 - 1) {
                    sb.append(", ");
                }
                i++;
            }
            sb.append(']');
            return;
        }
        if (obj instanceof float[]) {
            float[] fArr = (float[]) obj;
            sb.append('[');
            int length7 = fArr.length;
            while (i < length7) {
                sb.append(fArr[i]);
                if (i != length7 - 1) {
                    sb.append(", ");
                }
                i++;
            }
            sb.append(']');
            return;
        }
        if (obj instanceof double[]) {
            double[] dArr = (double[]) obj;
            sb.append('[');
            int length8 = dArr.length;
            while (i < length8) {
                sb.append(dArr[i]);
                if (i != length8 - 1) {
                    sb.append(", ");
                }
                i++;
            }
            sb.append(']');
            return;
        }
        Object[] objArr = (Object[]) obj;
        sb.append('[');
        if (map.containsKey(objArr)) {
            sb.append("...");
        } else {
            map.put(objArr, null);
            int length9 = objArr.length;
            while (i < length9) {
                b(sb, objArr[i], map);
                if (i != length9 - 1) {
                    sb.append(", ");
                }
                i++;
            }
            map.remove(objArr);
        }
        sb.append(']');
    }

    public static final EnumC1420a c(int i) {
        if (i == 0) {
            return EnumC1420a.a;
        }
        if (i == 1) {
            return EnumC1420a.b;
        }
        throw new IllegalArgumentException(AbstractC0147y.c(i, "Could not convert ", " to BackoffPolicy"));
    }

    public static final androidx.work.A d(int i) {
        if (i == 0) {
            return androidx.work.A.a;
        }
        if (i == 1) {
            return androidx.work.A.b;
        }
        if (i == 2) {
            return androidx.work.A.c;
        }
        if (i == 3) {
            return androidx.work.A.d;
        }
        if (i == 4) {
            return androidx.work.A.e;
        }
        if (Build.VERSION.SDK_INT < 30 || i != 5) {
            throw new IllegalArgumentException(AbstractC0147y.c(i, "Could not convert ", " to NetworkType"));
        }
        return androidx.work.A.f;
    }

    public static final androidx.work.J e(int i) {
        if (i == 0) {
            return androidx.work.J.a;
        }
        if (i == 1) {
            return androidx.work.J.b;
        }
        throw new IllegalArgumentException(AbstractC0147y.c(i, "Could not convert ", " to OutOfQuotaPolicy"));
    }

    public static final androidx.work.N f(int i) {
        if (i == 0) {
            return androidx.work.N.a;
        }
        if (i == 1) {
            return androidx.work.N.b;
        }
        if (i == 2) {
            return androidx.work.N.c;
        }
        if (i == 3) {
            return androidx.work.N.d;
        }
        if (i == 4) {
            return androidx.work.N.e;
        }
        if (i == 5) {
            return androidx.work.N.f;
        }
        throw new IllegalArgumentException(AbstractC0147y.c(i, "Could not convert ", " to State"));
    }

    public static final int g(androidx.work.N state) {
        Intrinsics.checkNotNullParameter(state, "state");
        int iOrdinal = state.ordinal();
        if (iOrdinal == 0) {
            return 0;
        }
        int i = 1;
        if (iOrdinal != 1) {
            i = 2;
            if (iOrdinal != 2) {
                i = 3;
                if (iOrdinal != 3) {
                    i = 4;
                    if (iOrdinal != 4) {
                        if (iOrdinal == 5) {
                            return 5;
                        }
                        throw new NoWhenBranchMatchedException();
                    }
                }
            }
        }
        return i;
    }

    public static final androidx.work.impl.utils.g h(byte[] bytes) throws IOException {
        Intrinsics.checkNotNullParameter(bytes, "bytes");
        if (Build.VERSION.SDK_INT < 28 || bytes.length == 0) {
            return new androidx.work.impl.utils.g(null);
        }
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bytes);
        try {
            ObjectInputStream objectInputStream = new ObjectInputStream(byteArrayInputStream);
            try {
                int i = objectInputStream.readInt();
                int[] iArr = new int[i];
                for (int i2 = 0; i2 < i; i2++) {
                    iArr[i2] = objectInputStream.readInt();
                }
                int i3 = objectInputStream.readInt();
                int[] iArr2 = new int[i3];
                for (int i4 = 0; i4 < i3; i4++) {
                    iArr2[i4] = objectInputStream.readInt();
                }
                androidx.work.impl.utils.g gVarA = E2.a(iArr2, iArr);
                objectInputStream.close();
                byteArrayInputStream.close();
                return gVarA;
            } finally {
            }
        } finally {
        }
    }
}

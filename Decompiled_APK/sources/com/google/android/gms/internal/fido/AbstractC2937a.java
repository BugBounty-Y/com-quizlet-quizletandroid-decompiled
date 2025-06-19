package com.google.android.gms.internal.fido;

import androidx.camera.camera2.internal.AbstractC0147y;
import com.comscore.streaming.EventType;
import com.google.android.gms.internal.ads.C1756Qb;
import com.j256.ormlite.stmt.query.SimpleComparison;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;
import java.io.IOException;
import java.math.RoundingMode;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.Comparator;
import java.util.Iterator;
import java.util.Map;
import java.util.SortedSet;
import java.util.TreeMap;
import java.util.logging.Level;
import java.util.logging.Logger;

/* renamed from: com.google.android.gms.internal.fido.a, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC2937a {
    public static volatile C1756Qb b;
    public static final Object a = new Object();
    public static final a0 c = new a0("id");
    public static final a0 d = new a0(DBUserFields.Names.USER_UPGRADE_TYPE);

    public static int a(int i, int i2) {
        RoundingMode roundingMode = RoundingMode.CEILING;
        roundingMode.getClass();
        if (i2 == 0) {
            throw new ArithmeticException("/ by zero");
        }
        int i3 = i / i2;
        int i4 = i - (i2 * i3);
        if (i4 == 0) {
            return i3;
        }
        int i5 = ((i ^ i2) >> 31) | 1;
        switch (N.a[roundingMode.ordinal()]) {
            case 1:
                throw new ArithmeticException("mode was UNNECESSARY, but rounding was necessary");
            case 2:
                return i3;
            case 3:
                if (i5 >= 0) {
                    return i3;
                }
                break;
            case 4:
                break;
            case 5:
                if (i5 <= 0) {
                    return i3;
                }
                break;
            case 6:
            case 7:
            case 8:
                int iAbs = Math.abs(i4);
                int iAbs2 = iAbs - (Math.abs(i2) - iAbs);
                if (iAbs2 == 0) {
                    RoundingMode roundingMode2 = RoundingMode.HALF_UP;
                    RoundingMode roundingMode3 = RoundingMode.HALF_EVEN;
                    return i3;
                }
                if (iAbs2 <= 0) {
                    return i3;
                }
                break;
            default:
                throw new AssertionError();
        }
        return i3 + i5;
    }

    public static int b(AbstractC2951o abstractC2951o) {
        Iterator it2 = abstractC2951o.iterator();
        int iHashCode = 0;
        while (it2.hasNext()) {
            Object next = it2.next();
            iHashCode += next != null ? next.hashCode() : 0;
        }
        return iHashCode;
    }

    public static String c(T t) {
        StringBuilder sb = new StringBuilder(t.e());
        for (int i = 0; i < t.e(); i++) {
            byte bA = t.a(i);
            if (bA == 34) {
                sb.append("\\\"");
            } else if (bA == 39) {
                sb.append("\\'");
            } else if (bA != 92) {
                switch (bA) {
                    case 7:
                        sb.append("\\a");
                        break;
                    case 8:
                        sb.append("\\b");
                        break;
                    case 9:
                        sb.append("\\t");
                        break;
                    case 10:
                        sb.append("\\n");
                        break;
                    case 11:
                        sb.append("\\v");
                        break;
                    case 12:
                        sb.append("\\f");
                        break;
                    case 13:
                        sb.append("\\r");
                        break;
                    default:
                        if (bA < 32 || bA > 126) {
                            sb.append('\\');
                            sb.append((char) (((bA >>> 6) & 3) + 48));
                            sb.append((char) (((bA >>> 3) & 7) + 48));
                            sb.append((char) ((bA & 7) + 48));
                            break;
                        } else {
                            sb.append((char) bA);
                            break;
                        }
                }
            } else {
                sb.append("\\\\");
            }
        }
        return sb.toString();
    }

    public static String d(String str, Object... objArr) {
        int length;
        int length2;
        int iIndexOf;
        String strE;
        int i = 0;
        int i2 = 0;
        while (true) {
            length = objArr.length;
            if (i2 >= length) {
                break;
            }
            Object obj = objArr[i2];
            if (obj == null) {
                strE = "null";
            } else {
                try {
                    strE = obj.toString();
                } catch (Exception e) {
                    String strL = android.support.v4.media.session.a.l(obj.getClass().getName(), "@", Integer.toHexString(System.identityHashCode(obj)));
                    Logger.getLogger("com.google.common.base.Strings").logp(Level.WARNING, "com.google.common.base.Strings", "lenientToString", "Exception during lenientFormat for ".concat(strL), (Throwable) e);
                    strE = AbstractC0147y.e(SimpleComparison.LESS_THAN_OPERATION, strL, " threw ", e.getClass().getName(), SimpleComparison.GREATER_THAN_OPERATION);
                }
            }
            objArr[i2] = strE;
            i2++;
        }
        StringBuilder sb = new StringBuilder(str.length() + (length * 16));
        int i3 = 0;
        while (true) {
            length2 = objArr.length;
            if (i >= length2 || (iIndexOf = str.indexOf("%s", i3)) == -1) {
                break;
            }
            sb.append((CharSequence) str, i3, iIndexOf);
            sb.append(objArr[i]);
            i++;
            i3 = iIndexOf + 2;
        }
        sb.append((CharSequence) str, i3, str.length());
        if (i < length2) {
            sb.append(" [");
            sb.append(objArr[i]);
            for (int i4 = i + 1; i4 < objArr.length; i4++) {
                sb.append(", ");
                sb.append(objArr[i4]);
            }
            sb.append(']');
        }
        return sb.toString();
    }

    public static void e(int i, int i2) {
        String strD;
        if (i < 0 || i >= i2) {
            if (i < 0) {
                strD = d("%s (%s) must not be negative", "index", Integer.valueOf(i));
            } else {
                if (i2 < 0) {
                    throw new IllegalArgumentException(android.support.v4.media.session.a.f(i2, "negative size: "));
                }
                strD = d("%s (%s) must be less than size (%s)", "index", Integer.valueOf(i), Integer.valueOf(i2));
            }
            throw new IndexOutOfBoundsException(strD);
        }
    }

    public static void f(Object obj, Object obj2) {
        if (obj == null) {
            throw new NullPointerException("null key in entry: null=".concat(String.valueOf(obj2)));
        }
        if (obj2 == null) {
            throw new NullPointerException(android.support.v4.media.session.a.B("null value in entry: ", obj.toString(), "=null"));
        }
    }

    public static final void g(StringBuilder sb, Iterator it2, assistantMode.utils.studiableMetadata.b bVar) {
        if (it2.hasNext()) {
            Map.Entry entry = (Map.Entry) it2.next();
            sb.append(assistantMode.utils.studiableMetadata.b.b0(entry.getKey()));
            sb.append(" : ");
            sb.append(assistantMode.utils.studiableMetadata.b.b0(entry.getValue()));
            while (it2.hasNext()) {
                sb.append(",\n  ");
                Map.Entry entry2 = (Map.Entry) it2.next();
                sb.append(assistantMode.utils.studiableMetadata.b.b0(entry2.getKey()));
                sb.append(" : ");
                sb.append(assistantMode.utils.studiableMetadata.b.b0(entry2.getValue()));
            }
        }
    }

    public static boolean h(Object obj, Object obj2) {
        if (obj != obj2) {
            return obj != null && obj.equals(obj2);
        }
        return true;
    }

    public static boolean j(Comparator comparator, Collection collection) {
        Object objComparator;
        comparator.getClass();
        collection.getClass();
        if (collection instanceof SortedSet) {
            objComparator = ((SortedSet) collection).comparator();
            if (objComparator == null) {
                objComparator = C2957v.b;
            }
        } else {
            if (!(collection instanceof C)) {
                return false;
            }
            objComparator = ((AbstractC2954s) ((C) collection)).d;
        }
        return comparator.equals(objComparator);
    }

    public static byte[] k(byte[]... bArr) {
        int i = 0;
        int length = 0;
        while (true) {
            if (i >= bArr.length) {
                break;
            }
            length += bArr[i].length;
            i++;
        }
        byte[] bArr2 = new byte[length];
        int i2 = 0;
        for (byte[] bArr3 : bArr) {
            int length2 = bArr3.length;
            System.arraycopy(bArr3, 0, bArr2, i2, length2);
            i2 += length2;
        }
        return bArr2;
    }

    public static final b0 l(d0 d0Var) throws zzhf, zzhj {
        try {
            c0 c0VarI = d0Var.i();
            if (c0VarI == null) {
                throw new zzhj("Parser being asked to parse an empty input stream");
            }
            try {
                try {
                    byte b2 = c0VarI.a;
                    byte b3 = c0VarI.b;
                    int i = 0;
                    if (b2 == Byte.MIN_VALUE) {
                        long jA = d0Var.a();
                        if (jA > 1000) {
                            throw new zzhj("Parser being asked to read a large CBOR array");
                        }
                        m(b3, jA);
                        b0[] b0VarArr = new b0[(int) jA];
                        while (i < jA) {
                            b0VarArr[i] = l(d0Var);
                            i++;
                        }
                        return new V(AbstractC2949m.m(b0VarArr));
                    }
                    if (b2 != -96) {
                        if (b2 == -64) {
                            throw new zzhj("Tags are currently unsupported");
                        }
                        if (b2 == -32) {
                            return new W(d0Var.j());
                        }
                        if (b2 == 0 || b2 == 32) {
                            long jD = d0Var.d();
                            m(b3, jD > 0 ? jD : ~jD);
                            return new Y(jD);
                        }
                        if (b2 == 64) {
                            d0Var.q((byte) 64);
                            byte[] bArrY = d0Var.y();
                            int length = bArrY.length;
                            m(b3, length);
                            return new X(T.k(length, bArrY));
                        }
                        if (b2 == 96) {
                            d0Var.q((byte) 96);
                            String str = new String(d0Var.y(), StandardCharsets.UTF_8);
                            m(b3, str.length());
                            return new a0(str);
                        }
                        throw new zzhj("Unidentifiable major type: " + ((b2 >> 5) & 7));
                    }
                    long jF = d0Var.f();
                    if (jF > 1000) {
                        throw new zzhj("Parser being asked to read a large CBOR map");
                    }
                    m(b3, jF);
                    int i2 = (int) jF;
                    androidx.work.impl.model.l[] lVarArr = new androidx.work.impl.model.l[i2];
                    b0 b0Var = null;
                    int i3 = 0;
                    while (i3 < jF) {
                        b0 b0VarL = l(d0Var);
                        if (b0Var != null && b0VarL.compareTo(b0Var) <= 0) {
                            throw new zzhf("Keys in CBOR Map not in strictly ascending natural order:\nPrevious key: " + b0Var.toString() + "\nCurrent key: " + b0VarL.toString());
                        }
                        lVarArr[i3] = new androidx.work.impl.model.l(b0VarL, false, l(d0Var), 10);
                        i3++;
                        b0Var = b0VarL;
                    }
                    TreeMap treeMap = new TreeMap();
                    while (i < i2) {
                        androidx.work.impl.model.l lVar = lVarArr[i];
                        if (treeMap.containsKey((b0) lVar.b)) {
                            throw new zzhf("Attempted to add duplicate key to canonical CBOR Map.");
                        }
                        treeMap.put((b0) lVar.b, (b0) lVar.c);
                        i++;
                    }
                    return new Z(r.b(treeMap));
                } catch (IOException | RuntimeException e) {
                    e = e;
                    throw new zzhj(e);
                }
            } catch (RuntimeException e2) {
                e = e2;
                throw new zzhj(e);
            }
        } catch (IOException e3) {
            throw new zzhj(e3);
        }
    }

    public static final void m(byte b2, long j) throws zzhf {
        switch (b2) {
            case EventType.VIDEO /* 24 */:
                if (j < 24) {
                    throw new zzhf(androidx.compose.animation.d0.o(j, "Integer value ", " after add info could have been represented in 0 additional bytes, but used 1"));
                }
                return;
            case EventType.SUBS /* 25 */:
                if (j < 256) {
                    throw new zzhf(androidx.compose.animation.d0.o(j, "Integer value ", " after add info could have been represented in 0-1 additional bytes, but used 2"));
                }
                return;
            case EventType.CDN /* 26 */:
                if (j < 65536) {
                    throw new zzhf(androidx.compose.animation.d0.o(j, "Integer value ", " after add info could have been represented in 0-2 additional bytes, but used 4"));
                }
                return;
            case 27:
                if (j < 4294967296L) {
                    throw new zzhf(androidx.compose.animation.d0.o(j, "Integer value ", " after add info could have been represented in 0-4 additional bytes, but used 8"));
                }
                return;
            default:
                return;
        }
    }

    public static void n(int i, int i2, int i3) {
        if (i < 0 || i2 < i || i2 > i3) {
            throw new IndexOutOfBoundsException((i < 0 || i > i3) ? o(i, i3, "start index") : (i2 < 0 || i2 > i3) ? o(i2, i3, "end index") : d("end index (%s) must not be less than start index (%s)", Integer.valueOf(i2), Integer.valueOf(i)));
        }
    }

    public static String o(int i, int i2, String str) {
        if (i < 0) {
            return d("%s (%s) must not be negative", str, Integer.valueOf(i));
        }
        if (i2 >= 0) {
            return d("%s (%s) must not be greater than size (%s)", str, Integer.valueOf(i), Integer.valueOf(i2));
        }
        throw new IllegalArgumentException(android.support.v4.media.session.a.f(i2, "negative size: "));
    }
}

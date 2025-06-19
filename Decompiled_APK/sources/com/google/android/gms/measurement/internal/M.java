package com.google.android.gms.measurement.internal;

import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.net.Uri;
import android.os.Bundle;
import android.os.Parcel;
import android.os.Parcelable;
import android.text.TextUtils;
import com.google.android.gms.ads.nonagon.signalgeneration.AbstractC1642h;
import com.google.android.gms.common.internal.safeparcel.SafeParcelReader$ParseException;
import com.google.android.gms.internal.ads.C2142hd;
import com.google.android.gms.internal.measurement.C2964a1;
import com.google.android.gms.internal.measurement.C2967b;
import com.google.android.gms.internal.measurement.C2969b1;
import com.google.android.gms.internal.measurement.C2974c1;
import com.google.android.gms.internal.measurement.C2989f1;
import com.google.android.gms.internal.measurement.C2999h1;
import com.google.android.gms.internal.measurement.C3000h2;
import com.google.android.gms.internal.measurement.C3009j1;
import com.google.android.gms.internal.measurement.C3014k1;
import com.google.android.gms.internal.measurement.C3019l1;
import com.google.android.gms.internal.measurement.C3038p0;
import com.google.android.gms.internal.measurement.C3052s0;
import com.google.android.gms.internal.measurement.C3054s2;
import com.google.android.gms.internal.measurement.C3062u0;
import com.google.android.gms.internal.measurement.C3067v0;
import com.google.android.gms.internal.measurement.E3;
import com.google.android.gms.internal.measurement.InterfaceC2970b2;
import com.google.android.gms.internal.measurement.InterfaceC2975c2;
import com.google.android.gms.internal.measurement.Q1;
import com.google.android.gms.internal.measurement.T1;
import com.google.android.gms.internal.measurement.V1;
import com.google.android.gms.internal.measurement.zzmm;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.BitSet;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.zip.GZIPOutputStream;

/* loaded from: classes2.dex */
public final class M extends m1 {
    public final /* synthetic */ int e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ M(r1 r1Var, int i) {
        super(r1Var);
        this.e = i;
    }

    public static ArrayList C0(BitSet bitSet) {
        int length = (bitSet.length() + 63) / 64;
        ArrayList arrayList = new ArrayList(length);
        for (int i = 0; i < length; i++) {
            long j = 0;
            for (int i2 = 0; i2 < 64; i2++) {
                int i3 = (i * 64) + i2;
                if (i3 >= bitSet.length()) {
                    break;
                }
                if (bitSet.get(i3)) {
                    j |= 1 << i2;
                }
            }
            arrayList.add(Long.valueOf(j));
        }
        return arrayList;
    }

    public static HashMap D0(Bundle bundle, boolean z) {
        HashMap map = new HashMap();
        for (String str : bundle.keySet()) {
            Object obj = bundle.get(str);
            boolean z2 = obj instanceof Parcelable[];
            if (z2 || (obj instanceof ArrayList) || (obj instanceof Bundle)) {
                if (z) {
                    ArrayList arrayList = new ArrayList();
                    if (z2) {
                        for (Parcelable parcelable : (Parcelable[]) obj) {
                            if (parcelable instanceof Bundle) {
                                arrayList.add(D0((Bundle) parcelable, false));
                            }
                        }
                    } else if (obj instanceof ArrayList) {
                        ArrayList arrayList2 = (ArrayList) obj;
                        int size = arrayList2.size();
                        for (int i = 0; i < size; i++) {
                            Object obj2 = arrayList2.get(i);
                            if (obj2 instanceof Bundle) {
                                arrayList.add(D0((Bundle) obj2, false));
                            }
                        }
                    } else if (obj instanceof Bundle) {
                        arrayList.add(D0((Bundle) obj, false));
                    }
                    map.put(str, arrayList);
                }
            } else if (obj != null) {
                map.put(str, obj);
            }
        }
        return map;
    }

    public static boolean G0(InterfaceC2970b2 interfaceC2970b2, int i) {
        if (i < ((C3000h2) interfaceC2970b2).c * 64) {
            return ((1 << (i % 64)) & ((Long) ((C3000h2) interfaceC2970b2).get(i / 64)).longValue()) != 0;
        }
        return false;
    }

    public static boolean W(String str) {
        return str != null && str.matches("([+-])?([0-9]+\\.?[0-9]*|[0-9]*\\.?[0-9]+)") && str.length() <= 310;
    }

    public static Bundle[] Y(InterfaceC2975c2 interfaceC2975c2) {
        ArrayList arrayList = new ArrayList();
        Iterator it2 = interfaceC2975c2.iterator();
        while (it2.hasNext()) {
            com.google.android.gms.internal.measurement.X0 x0 = (com.google.android.gms.internal.measurement.X0) it2.next();
            if (x0 != null) {
                Bundle bundle = new Bundle();
                for (com.google.android.gms.internal.measurement.X0 x02 : x0.u()) {
                    if (x02.J()) {
                        bundle.putString(x02.s(), x02.t());
                    } else if (x02.H()) {
                        bundle.putLong(x02.s(), x02.q());
                    } else if (x02.F()) {
                        bundle.putDouble(x02.s(), x02.n());
                    }
                }
                if (!bundle.isEmpty()) {
                    arrayList.add(bundle);
                }
            }
        }
        return (Bundle[]) arrayList.toArray(new Bundle[arrayList.size()]);
    }

    public static final void Z(com.google.android.gms.internal.measurement.T0 t0, String str, Long l) {
        List listP = t0.p();
        int i = 0;
        while (true) {
            if (i >= listP.size()) {
                i = -1;
                break;
            } else if (str.equals(((com.google.android.gms.internal.measurement.X0) listP.get(i)).s())) {
                break;
            } else {
                i++;
            }
        }
        com.google.android.gms.internal.measurement.W0 w0R = com.google.android.gms.internal.measurement.X0.r();
        w0R.k(str);
        w0R.i(l.longValue());
        if (i < 0) {
            t0.l(w0R);
        } else {
            t0.h();
            com.google.android.gms.internal.measurement.U0.A((com.google.android.gms.internal.measurement.U0) t0.b, i, (com.google.android.gms.internal.measurement.X0) w0R.f());
        }
    }

    public static final Bundle a0(List list) {
        Bundle bundle = new Bundle();
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            com.google.android.gms.internal.measurement.X0 x0 = (com.google.android.gms.internal.measurement.X0) it2.next();
            String strS = x0.s();
            if (x0.F()) {
                bundle.putDouble(strS, x0.n());
            } else if (x0.G()) {
                bundle.putFloat(strS, x0.o());
            } else if (x0.J()) {
                bundle.putString(strS, x0.t());
            } else if (x0.H()) {
                bundle.putLong(strS, x0.q());
            }
        }
        return bundle;
    }

    public static final com.google.android.gms.internal.measurement.X0 b0(com.google.android.gms.internal.measurement.U0 u0, String str) {
        for (com.google.android.gms.internal.measurement.X0 x0 : u0.u()) {
            if (x0.s().equals(str)) {
                return x0;
            }
        }
        return null;
    }

    /* JADX WARN: Type inference failed for: r0v6, types: [android.os.Bundle[], java.io.Serializable] */
    public static final Serializable c0(com.google.android.gms.internal.measurement.U0 u0, String str) {
        com.google.android.gms.internal.measurement.X0 x0B0 = b0(u0, str);
        if (x0B0 == null) {
            return null;
        }
        if (x0B0.J()) {
            return x0B0.t();
        }
        if (x0B0.H()) {
            return Long.valueOf(x0B0.q());
        }
        if (x0B0.F()) {
            return Double.valueOf(x0B0.n());
        }
        if (x0B0.p() > 0) {
            return Y((InterfaceC2975c2) x0B0.u());
        }
        return null;
    }

    public static final void f0(StringBuilder sb, int i) {
        for (int i2 = 0; i2 < i; i2++) {
            sb.append("  ");
        }
    }

    public static final void g0(Uri.Builder builder, String str, String str2, Set set) {
        if (set.contains(str) || TextUtils.isEmpty(str2)) {
            return;
        }
        builder.appendQueryParameter(str, str2);
    }

    public static final String h0(boolean z, boolean z2, boolean z3) {
        StringBuilder sb = new StringBuilder();
        if (z) {
            sb.append("Dynamic ");
        }
        if (z2) {
            sb.append("Sequence ");
        }
        if (z3) {
            sb.append("Session-Scoped ");
        }
        return sb.toString();
    }

    public static final void i0(Uri.Builder builder, String[] strArr, Bundle bundle, Set set) {
        for (String str : strArr) {
            String[] strArrSplit = str.split(",");
            String str2 = strArrSplit[0];
            String str3 = strArrSplit[strArrSplit.length - 1];
            String string = bundle.getString(str2);
            if (string != null) {
                g0(builder, str3, string, set);
            }
        }
    }

    public static final void j0(StringBuilder sb, String str, C2989f1 c2989f1) {
        if (c2989f1 == null) {
            return;
        }
        f0(sb, 3);
        sb.append(str);
        sb.append(" {\n");
        if (c2989f1.o() != 0) {
            f0(sb, 4);
            sb.append("results: ");
            int i = 0;
            for (Long l : c2989f1.u()) {
                int i2 = i + 1;
                if (i != 0) {
                    sb.append(", ");
                }
                sb.append(l);
                i = i2;
            }
            sb.append('\n');
        }
        if (c2989f1.q() != 0) {
            f0(sb, 4);
            sb.append("status: ");
            int i3 = 0;
            for (Long l2 : c2989f1.w()) {
                int i4 = i3 + 1;
                if (i3 != 0) {
                    sb.append(", ");
                }
                sb.append(l2);
                i3 = i4;
            }
            sb.append('\n');
        }
        if (c2989f1.n() != 0) {
            f0(sb, 4);
            sb.append("dynamic_filter_timestamps: {");
            int i5 = 0;
            for (com.google.android.gms.internal.measurement.S0 s0 : c2989f1.t()) {
                int i6 = i5 + 1;
                if (i5 != 0) {
                    sb.append(", ");
                }
                sb.append(s0.t() ? Integer.valueOf(s0.n()) : null);
                sb.append(":");
                sb.append(s0.s() ? Long.valueOf(s0.o()) : null);
                i5 = i6;
            }
            sb.append("}\n");
        }
        if (c2989f1.p() != 0) {
            f0(sb, 4);
            sb.append("sequence_filter_timestamps: {");
            int i7 = 0;
            for (C2999h1 c2999h1 : c2989f1.v()) {
                int i8 = i7 + 1;
                if (i7 != 0) {
                    sb.append(", ");
                }
                sb.append(c2999h1.u() ? Integer.valueOf(c2999h1.o()) : null);
                sb.append(": [");
                Iterator it2 = c2999h1.r().iterator();
                int i9 = 0;
                while (it2.hasNext()) {
                    long jLongValue = ((Long) it2.next()).longValue();
                    int i10 = i9 + 1;
                    if (i9 != 0) {
                        sb.append(", ");
                    }
                    sb.append(jLongValue);
                    i9 = i10;
                }
                sb.append("]");
                i7 = i8;
            }
            sb.append("}\n");
        }
        f0(sb, 3);
        sb.append("}\n");
    }

    public static final void k0(StringBuilder sb, int i, String str, Object obj) {
        if (obj == null) {
            return;
        }
        f0(sb, i + 1);
        sb.append(str);
        sb.append(": ");
        sb.append(obj);
        sb.append('\n');
    }

    public static final void l0(StringBuilder sb, int i, String str, C3052s0 c3052s0) {
        if (c3052s0 == null) {
            return;
        }
        f0(sb, i);
        sb.append(str);
        sb.append(" {\n");
        if (c3052s0.s()) {
            int iX = c3052s0.x();
            k0(sb, i, "comparison_type", iX != 1 ? iX != 2 ? iX != 3 ? iX != 4 ? "BETWEEN" : "EQUAL" : "GREATER_THAN" : "LESS_THAN" : "UNKNOWN_COMPARISON_TYPE");
        }
        if (c3052s0.u()) {
            k0(sb, i, "match_as_float", Boolean.valueOf(c3052s0.r()));
        }
        if (c3052s0.t()) {
            k0(sb, i, "comparison_value", c3052s0.o());
        }
        if (c3052s0.w()) {
            k0(sb, i, "min_comparison_value", c3052s0.q());
        }
        if (c3052s0.v()) {
            k0(sb, i, "max_comparison_value", c3052s0.p());
        }
        f0(sb, i);
        sb.append("}\n");
    }

    public static int m0(C2969b1 c2969b1, String str) {
        for (int i = 0; i < ((C2974c1) c2969b1.b).U1(); i++) {
            if (str.equals(((C2974c1) c2969b1.b).p(i).s())) {
                return i;
            }
        }
        return -1;
    }

    private final void n0() {
    }

    private final void o0() {
    }

    private final void p0() {
    }

    public static Bundle t0(Map map, boolean z) {
        Bundle bundle = new Bundle();
        for (String str : map.keySet()) {
            Object obj = map.get(str);
            if (obj == null) {
                bundle.putString(str, null);
            } else if (obj instanceof Long) {
                bundle.putLong(str, ((Long) obj).longValue());
            } else if (obj instanceof Double) {
                bundle.putDouble(str, ((Double) obj).doubleValue());
            } else if (!(obj instanceof ArrayList)) {
                bundle.putString(str, obj.toString());
            } else if (z) {
                ArrayList arrayList = (ArrayList) obj;
                ArrayList arrayList2 = new ArrayList();
                int size = arrayList.size();
                for (int i = 0; i < size; i++) {
                    arrayList2.add(t0((Map) arrayList.get(i), false));
                }
                bundle.putParcelableArray(str, (Parcelable[]) arrayList2.toArray(new Parcelable[0]));
            }
        }
        return bundle;
    }

    public static zzbh v0(C2967b c2967b) {
        Object obj;
        Bundle bundleT0 = t0(c2967b.c, true);
        String string = (!bundleT0.containsKey("_o") || (obj = bundleT0.get("_o")) == null) ? "app" : obj.toString();
        String strD = AbstractC3883n0.d(c2967b.a, AbstractC3883n0.a, AbstractC3883n0.c);
        if (strD == null) {
            strD = c2967b.a;
        }
        return new zzbh(strD, new zzbf(bundleT0), string, c2967b.b);
    }

    public static V1 y0(V1 v1, byte[] bArr) throws zzmm {
        Q1 q1D;
        Q1 q1 = Q1.a;
        if (q1 == null) {
            synchronized (Q1.class) {
                try {
                    q1D = Q1.a;
                    if (q1D == null) {
                        C3054s2 c3054s2 = C3054s2.c;
                        q1D = T1.d();
                        Q1.a = q1D;
                    }
                } finally {
                }
            }
            q1 = q1D;
        }
        if (q1 != null) {
            v1.getClass();
            v1.e(bArr, bArr.length, q1);
            return v1;
        }
        v1.getClass();
        int length = bArr.length;
        Q1 q12 = Q1.a;
        C3054s2 c3054s22 = C3054s2.c;
        v1.e(bArr, length, Q1.b);
        return v1;
    }

    public String A0(C3062u0 c3062u0) {
        StringBuilder sbU = androidx.compose.animation.d0.u("\nproperty_filter {\n");
        if (c3062u0.v()) {
            k0(sbU, 0, "filter_id", Integer.valueOf(c3062u0.n()));
        }
        k0(sbU, 0, "property_name", ((Y) this.b).m.f(c3062u0.q()));
        String strH0 = h0(c3062u0.s(), c3062u0.t(), c3062u0.u());
        if (!strH0.isEmpty()) {
            k0(sbU, 0, "filter_type", strH0);
        }
        e0(sbU, 1, c3062u0.o());
        sbU.append("}\n");
        return sbU.toString();
    }

    public List B0(InterfaceC2970b2 interfaceC2970b2, List list) {
        int i;
        ArrayList arrayList = new ArrayList(interfaceC2970b2);
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            Integer num = (Integer) it2.next();
            int iIntValue = num.intValue();
            Y y = (Y) this.b;
            if (iIntValue < 0) {
                I i2 = y.i;
                Y.k(i2);
                i2.j.g("Ignoring negative bit index to be cleared", num);
            } else {
                int iIntValue2 = num.intValue() / 64;
                if (iIntValue2 >= arrayList.size()) {
                    I i3 = y.i;
                    Y.k(i3);
                    i3.j.h("Ignoring bit index greater than bitSet size", num, Integer.valueOf(arrayList.size()));
                } else {
                    arrayList.set(iIntValue2, Long.valueOf(((Long) arrayList.get(iIntValue2)).longValue() & (~(1 << (num.intValue() % 64)))));
                }
            }
        }
        int size = arrayList.size();
        int size2 = arrayList.size() - 1;
        while (true) {
            int i4 = size2;
            i = size;
            size = i4;
            if (size < 0 || ((Long) arrayList.get(size)).longValue() != 0) {
                break;
            }
            size2 = size - 1;
        }
        return arrayList.subList(0, i);
    }

    public void E0(com.google.android.gms.internal.measurement.W0 w0, Object obj) {
        w0.h();
        com.google.android.gms.internal.measurement.X0.A((com.google.android.gms.internal.measurement.X0) w0.b);
        w0.h();
        com.google.android.gms.internal.measurement.X0.y((com.google.android.gms.internal.measurement.X0) w0.b);
        w0.h();
        com.google.android.gms.internal.measurement.X0.x((com.google.android.gms.internal.measurement.X0) w0.b);
        w0.h();
        com.google.android.gms.internal.measurement.X0.z((com.google.android.gms.internal.measurement.X0) w0.b);
        if (obj instanceof String) {
            w0.l((String) obj);
            return;
        }
        if (obj instanceof Long) {
            w0.i(((Long) obj).longValue());
            return;
        }
        if (obj instanceof Double) {
            double dDoubleValue = ((Double) obj).doubleValue();
            w0.h();
            com.google.android.gms.internal.measurement.X0.B((com.google.android.gms.internal.measurement.X0) w0.b, dDoubleValue);
            return;
        }
        if (!(obj instanceof Bundle[])) {
            I i = ((Y) this.b).i;
            Y.k(i);
            i.g.g("Ignoring invalid (type) event param value", obj);
            return;
        }
        ArrayList arrayList = new ArrayList();
        for (Bundle bundle : (Bundle[]) obj) {
            if (bundle != null) {
                com.google.android.gms.internal.measurement.W0 w0R = com.google.android.gms.internal.measurement.X0.r();
                for (String str : bundle.keySet()) {
                    com.google.android.gms.internal.measurement.W0 w0R2 = com.google.android.gms.internal.measurement.X0.r();
                    w0R2.k(str);
                    Object obj2 = bundle.get(str);
                    if (obj2 instanceof Long) {
                        w0R2.i(((Long) obj2).longValue());
                    } else if (obj2 instanceof String) {
                        w0R2.l((String) obj2);
                    } else if (obj2 instanceof Double) {
                        double dDoubleValue2 = ((Double) obj2).doubleValue();
                        w0R2.h();
                        com.google.android.gms.internal.measurement.X0.B((com.google.android.gms.internal.measurement.X0) w0R2.b, dDoubleValue2);
                    }
                    w0R.h();
                    com.google.android.gms.internal.measurement.X0.w((com.google.android.gms.internal.measurement.X0) w0R.b, (com.google.android.gms.internal.measurement.X0) w0R2.f());
                }
                if (((com.google.android.gms.internal.measurement.X0) w0R.b).p() > 0) {
                    arrayList.add((com.google.android.gms.internal.measurement.X0) w0R.f());
                }
            }
        }
        w0.h();
        com.google.android.gms.internal.measurement.X0.v((com.google.android.gms.internal.measurement.X0) w0.b, arrayList);
    }

    public void F0(C3014k1 c3014k1, Object obj) {
        com.google.android.gms.common.internal.u.h(obj);
        c3014k1.h();
        C3019l1.w((C3019l1) c3014k1.b);
        c3014k1.h();
        C3019l1.v((C3019l1) c3014k1.b);
        c3014k1.h();
        C3019l1.u((C3019l1) c3014k1.b);
        if (obj instanceof String) {
            c3014k1.h();
            C3019l1.B((C3019l1) c3014k1.b, (String) obj);
        } else if (obj instanceof Long) {
            long jLongValue = ((Long) obj).longValue();
            c3014k1.h();
            C3019l1.y((C3019l1) c3014k1.b, jLongValue);
        } else if (obj instanceof Double) {
            double dDoubleValue = ((Double) obj).doubleValue();
            c3014k1.h();
            C3019l1.x((C3019l1) c3014k1.b, dDoubleValue);
        } else {
            I i = ((Y) this.b).i;
            Y.k(i);
            i.g.g("Ignoring invalid (type) user attribute value", obj);
        }
    }

    public boolean H0(long j, long j2) {
        if (j == 0 || j2 <= 0) {
            return true;
        }
        ((Y) this.b).n.getClass();
        return Math.abs(System.currentTimeMillis() - j) > j2;
    }

    @Override // com.google.android.gms.measurement.internal.m1
    public final void V() {
        int i = this.e;
    }

    public byte[] X(byte[] bArr) throws IOException {
        try {
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            GZIPOutputStream gZIPOutputStream = new GZIPOutputStream(byteArrayOutputStream);
            gZIPOutputStream.write(bArr);
            gZIPOutputStream.close();
            byteArrayOutputStream.close();
            return byteArrayOutputStream.toByteArray();
        } catch (IOException e) {
            I i = ((Y) this.b).i;
            Y.k(i);
            i.g.g("Failed to gzip content", e);
            throw e;
        }
    }

    public void d0(StringBuilder sb, int i, InterfaceC2975c2 interfaceC2975c2) {
        if (interfaceC2975c2 == null) {
            return;
        }
        int i2 = i + 1;
        Iterator it2 = interfaceC2975c2.iterator();
        while (it2.hasNext()) {
            com.google.android.gms.internal.measurement.X0 x0 = (com.google.android.gms.internal.measurement.X0) it2.next();
            if (x0 != null) {
                f0(sb, i2);
                sb.append("param {\n");
                k0(sb, i2, "name", x0.I() ? ((Y) this.b).m.e(x0.s()) : null);
                k0(sb, i2, "string_value", x0.J() ? x0.t() : null);
                k0(sb, i2, "int_value", x0.H() ? Long.valueOf(x0.q()) : null);
                k0(sb, i2, "double_value", x0.F() ? Double.valueOf(x0.n()) : null);
                if (x0.p() > 0) {
                    d0(sb, i2, (InterfaceC2975c2) x0.u());
                }
                f0(sb, i2);
                sb.append("}\n");
            }
        }
    }

    public void e0(StringBuilder sb, int i, C3038p0 c3038p0) {
        String str;
        if (c3038p0 == null) {
            return;
        }
        f0(sb, i);
        sb.append("filter {\n");
        if (c3038p0.t()) {
            k0(sb, i, "complement", Boolean.valueOf(c3038p0.s()));
        }
        if (c3038p0.v()) {
            k0(sb, i, "param_name", ((Y) this.b).m.e(c3038p0.q()));
        }
        if (c3038p0.w()) {
            int i2 = i + 1;
            C3067v0 c3067v0P = c3038p0.p();
            if (c3067v0P != null) {
                f0(sb, i2);
                sb.append("string_filter {\n");
                if (c3067v0P.u()) {
                    switch (c3067v0P.v()) {
                        case 1:
                            str = "UNKNOWN_MATCH_TYPE";
                            break;
                        case 2:
                            str = "REGEXP";
                            break;
                        case 3:
                            str = "BEGINS_WITH";
                            break;
                        case 4:
                            str = "ENDS_WITH";
                            break;
                        case 5:
                            str = "PARTIAL";
                            break;
                        case 6:
                            str = "EXACT";
                            break;
                        default:
                            str = "IN_LIST";
                            break;
                    }
                    k0(sb, i2, "match_type", str);
                }
                if (c3067v0P.t()) {
                    k0(sb, i2, "expression", c3067v0P.p());
                }
                if (c3067v0P.s()) {
                    k0(sb, i2, "case_sensitive", Boolean.valueOf(c3067v0P.r()));
                }
                if (c3067v0P.n() > 0) {
                    f0(sb, i + 2);
                    sb.append("expression_list {\n");
                    for (String str2 : c3067v0P.q()) {
                        f0(sb, i + 3);
                        sb.append(str2);
                        sb.append("\n");
                    }
                    sb.append("}\n");
                }
                f0(sb, i2);
                sb.append("}\n");
            }
        }
        if (c3038p0.u()) {
            l0(sb, i + 1, "number_filter", c3038p0.o());
        }
        f0(sb, i);
        sb.append("}\n");
    }

    public void q0(String str, n1 n1Var, C2964a1 c2964a1, K k) {
        String str2;
        URL url;
        byte[] bArrC;
        X x;
        Map map;
        String str3 = n1Var.a;
        Y y = (Y) this.b;
        S();
        T();
        try {
            url = new URI(str3).toURL();
            this.c.a();
            bArrC = c2964a1.c();
            x = y.j;
            Y.k(x);
            map = n1Var.b;
            if (map == null) {
                map = Collections.EMPTY_MAP;
            }
            str2 = str;
        } catch (IllegalArgumentException | MalformedURLException | URISyntaxException unused) {
            str2 = str;
        }
        try {
            x.b0(new L(this, str2, url, bArrC, map, k));
        } catch (IllegalArgumentException | MalformedURLException | URISyntaxException unused2) {
            I i = y.i;
            Y.k(i);
            i.g.h("Failed to parse URL. Not uploading MeasurementBatch. appId", I.a0(str2), str3);
        }
    }

    public boolean r0() {
        T();
        ConnectivityManager connectivityManager = (ConnectivityManager) ((Y) this.b).a.getSystemService("connectivity");
        NetworkInfo activeNetworkInfo = null;
        if (connectivityManager != null) {
            try {
                activeNetworkInfo = connectivityManager.getActiveNetworkInfo();
            } catch (SecurityException unused) {
            }
        }
        return activeNetworkInfo != null && activeNetworkInfo.isConnected();
    }

    public long s0(byte[] bArr) {
        com.google.android.gms.common.internal.u.h(bArr);
        Y y = (Y) this.b;
        x1 x1Var = y.l;
        Y.h(x1Var);
        x1Var.S();
        MessageDigest messageDigestC0 = x1.c0();
        if (messageDigestC0 != null) {
            return x1.a1(messageDigestC0.digest(bArr));
        }
        I i = y.i;
        Y.k(i);
        i.g.f("Failed to get MD5");
        return 0L;
    }

    public Parcelable u0(byte[] bArr, Parcelable.Creator creator) {
        Parcelable parcelable = null;
        if (bArr == null) {
            return null;
        }
        Parcel parcelObtain = Parcel.obtain();
        try {
            try {
                parcelObtain.unmarshall(bArr, 0, bArr.length);
                parcelObtain.setDataPosition(0);
                parcelable = (Parcelable) creator.createFromParcel(parcelObtain);
            } catch (SafeParcelReader$ParseException unused) {
                I i = ((Y) this.b).i;
                Y.k(i);
                i.g.f("Failed to load parcelable from buffer");
            }
            return parcelable;
        } finally {
            parcelObtain.recycle();
        }
    }

    public zzov w0(String str, C2969b1 c2969b1, com.google.android.gms.internal.measurement.T0 t0, String str2) {
        int iIndexOf;
        E3.b();
        Y y = (Y) this.b;
        if (!y.g.f0(str, AbstractC3893t.V0)) {
            return null;
        }
        y.n.getClass();
        long jCurrentTimeMillis = System.currentTimeMillis();
        C3891s c3891s = AbstractC3893t.t0;
        C3864e c3864e = y.g;
        String[] strArrSplit = c3864e.e0(str, c3891s).split(",");
        HashSet hashSet = new HashSet(strArrSplit.length);
        for (String str3 : strArrSplit) {
            Objects.requireNonNull(str3);
            if (!hashSet.add(str3)) {
                throw new IllegalArgumentException("duplicate element: ".concat(str3));
            }
        }
        Set setUnmodifiableSet = Collections.unmodifiableSet(hashSet);
        r1 r1Var = this.c;
        o1 o1Var = r1Var.j;
        T t = o1Var.c.a;
        r1.L(t);
        String strI0 = t.i0(str);
        Uri.Builder builder = new Uri.Builder();
        Y y2 = (Y) o1Var.b;
        builder.scheme(y2.g.e0(str, AbstractC3893t.m0));
        boolean zIsEmpty = TextUtils.isEmpty(strI0);
        C3864e c3864e2 = y2.g;
        if (zIsEmpty) {
            builder.authority(c3864e2.e0(str, AbstractC3893t.n0));
        } else {
            builder.authority(strI0 + "." + c3864e2.e0(str, AbstractC3893t.n0));
        }
        builder.path(c3864e2.e0(str, AbstractC3893t.o0));
        g0(builder, "gmp_app_id", ((C2974c1) c2969b1.b).B(), setUnmodifiableSet);
        c3864e.Z();
        g0(builder, "gmp_version", String.valueOf(119002L), setUnmodifiableSet);
        String strS = ((C2974c1) c2969b1.b).s();
        C3891s c3891s2 = AbstractC3893t.Y0;
        boolean zF0 = c3864e.f0(str, c3891s2);
        T t2 = r1Var.a;
        if (zF0) {
            r1.L(t2);
            if (t2.W(str)) {
                strS = "";
            }
        }
        g0(builder, "app_instance_id", strS, setUnmodifiableSet);
        g0(builder, "rdid", ((C2974c1) c2969b1.b).F(), setUnmodifiableSet);
        g0(builder, "bundle_id", c2969b1.z(), setUnmodifiableSet);
        String strO = t0.o();
        String strD = AbstractC3883n0.d(strO, AbstractC3883n0.c, AbstractC3883n0.a);
        if (true != TextUtils.isEmpty(strD)) {
            strO = strD;
        }
        g0(builder, "app_event_name", strO, setUnmodifiableSet);
        g0(builder, "app_version", String.valueOf(((C2974c1) c2969b1.b).M0()), setUnmodifiableSet);
        String strD2 = ((C2974c1) c2969b1.b).D();
        if (c3864e.f0(str, c3891s2)) {
            r1.L(t2);
            if (t2.X(str) && !TextUtils.isEmpty(strD2) && (iIndexOf = strD2.indexOf(".")) != -1) {
                strD2 = strD2.substring(0, iIndexOf);
            }
        }
        g0(builder, "os_version", strD2, setUnmodifiableSet);
        g0(builder, "timestamp", String.valueOf(t0.k()), setUnmodifiableSet);
        if (((C2974c1) c2969b1.b).H1()) {
            g0(builder, "lat", "1", setUnmodifiableSet);
        }
        g0(builder, "privacy_sandbox_version", String.valueOf(((C2974c1) c2969b1.b).M()), setUnmodifiableSet);
        g0(builder, "trigger_uri_source", "1", setUnmodifiableSet);
        g0(builder, "trigger_uri_timestamp", String.valueOf(jCurrentTimeMillis), setUnmodifiableSet);
        g0(builder, "request_uuid", str2, setUnmodifiableSet);
        List<com.google.android.gms.internal.measurement.X0> listP = t0.p();
        Bundle bundle = new Bundle();
        for (com.google.android.gms.internal.measurement.X0 x0 : listP) {
            String strS2 = x0.s();
            if (x0.F()) {
                bundle.putString(strS2, String.valueOf(x0.n()));
            } else if (x0.G()) {
                bundle.putString(strS2, String.valueOf(x0.o()));
            } else if (x0.J()) {
                bundle.putString(strS2, x0.t());
            } else if (x0.H()) {
                bundle.putString(strS2, String.valueOf(x0.q()));
            }
        }
        i0(builder, c3864e.e0(str, AbstractC3893t.s0).split("\\|"), bundle, setUnmodifiableSet);
        List<C3019l1> listUnmodifiableList = Collections.unmodifiableList(((C2974c1) c2969b1.b).K());
        Bundle bundle2 = new Bundle();
        for (C3019l1 c3019l1 : listUnmodifiableList) {
            String strS3 = c3019l1.s();
            if (c3019l1.C()) {
                bundle2.putString(strS3, String.valueOf(c3019l1.n()));
            } else if (c3019l1.D()) {
                bundle2.putString(strS3, String.valueOf(c3019l1.o()));
            } else if (c3019l1.G()) {
                bundle2.putString(strS3, c3019l1.t());
            } else if (c3019l1.E()) {
                bundle2.putString(strS3, String.valueOf(c3019l1.p()));
            }
        }
        i0(builder, c3864e.e0(str, AbstractC3893t.r0).split("\\|"), bundle2, setUnmodifiableSet);
        g0(builder, "dma", true != ((C2974c1) c2969b1.b).G1() ? "0" : "1", setUnmodifiableSet);
        if (!((C2974c1) c2969b1.b).x().isEmpty()) {
            g0(builder, "dma_cps", ((C2974c1) c2969b1.b).x(), setUnmodifiableSet);
        }
        if (((C2974c1) c2969b1.b).J1()) {
            com.google.android.gms.internal.measurement.L0 l0H2 = ((C2974c1) c2969b1.b).h2();
            if (!l0H2.B().isEmpty()) {
                g0(builder, "dl_gclid", l0H2.B(), setUnmodifiableSet);
            }
            if (!l0H2.A().isEmpty()) {
                g0(builder, "dl_gbraid", l0H2.A(), setUnmodifiableSet);
            }
            if (!l0H2.z().isEmpty()) {
                g0(builder, "dl_gs", l0H2.z(), setUnmodifiableSet);
            }
            if (l0H2.v() > 0) {
                g0(builder, "dl_ss_ts", String.valueOf(l0H2.v()), setUnmodifiableSet);
            }
            if (!l0H2.E().isEmpty()) {
                g0(builder, "mr_gclid", l0H2.E(), setUnmodifiableSet);
            }
            if (!l0H2.D().isEmpty()) {
                g0(builder, "mr_gbraid", l0H2.D(), setUnmodifiableSet);
            }
            if (!l0H2.C().isEmpty()) {
                g0(builder, "mr_gs", l0H2.C(), setUnmodifiableSet);
            }
            if (l0H2.w() > 0) {
                g0(builder, "mr_click_ts", String.valueOf(l0H2.w()), setUnmodifiableSet);
            }
        }
        return new zzov(1, jCurrentTimeMillis, builder.build().toString());
    }

    public com.google.android.gms.internal.measurement.U0 x0(C2142hd c2142hd) {
        Bundle bundle;
        com.google.android.gms.internal.measurement.T0 t0R = com.google.android.gms.internal.measurement.U0.r();
        t0R.h();
        com.google.android.gms.internal.measurement.U0.B(c2142hd.c, (com.google.android.gms.internal.measurement.U0) t0R.b);
        zzbf zzbfVar = (zzbf) c2142hd.g;
        Iterator<String> it2 = zzbfVar.a.keySet().iterator();
        while (true) {
            boolean zHasNext = it2.hasNext();
            bundle = zzbfVar.a;
            if (!zHasNext) {
                break;
            }
            String next = it2.next();
            com.google.android.gms.internal.measurement.W0 w0R = com.google.android.gms.internal.measurement.X0.r();
            w0R.k(next);
            Object obj = bundle.get(next);
            com.google.android.gms.common.internal.u.h(obj);
            E0(w0R, obj);
            t0R.l(w0R);
        }
        String str = (String) c2142hd.f;
        if (!TextUtils.isEmpty(str) && bundle.get("_o") == null) {
            com.google.android.gms.internal.measurement.W0 w0R2 = com.google.android.gms.internal.measurement.X0.r();
            w0R2.k("_o");
            w0R2.l(str);
            t0R.m((com.google.android.gms.internal.measurement.X0) w0R2.f());
        }
        return (com.google.android.gms.internal.measurement.U0) t0R.f();
    }

    public String z0(C2964a1 c2964a1) {
        com.google.android.gms.internal.measurement.O0 o0I2;
        StringBuilder sbU = androidx.compose.animation.d0.u("\nbatch {\n");
        if (c2964a1.B()) {
            k0(sbU, 0, "upload_subdomain", c2964a1.s());
        }
        if (c2964a1.A()) {
            k0(sbU, 0, "sgtm_join_id", c2964a1.r());
        }
        for (C2974c1 c2974c1 : c2964a1.t()) {
            if (c2974c1 != null) {
                f0(sbU, 1);
                sbU.append("bundle {\n");
                if (c2974c1.d1()) {
                    k0(sbU, 1, "protocol_version", Integer.valueOf(c2974c1.R1()));
                }
                Y y = (Y) this.b;
                if (y.g.f0(c2974c1.r(), AbstractC3893t.L0) && c2974c1.g1()) {
                    k0(sbU, 1, "session_stitching_token", c2974c1.G());
                }
                k0(sbU, 1, "platform", c2974c1.E());
                if (c2974c1.Y0()) {
                    k0(sbU, 1, "gmp_version", Long.valueOf(c2974c1.a2()));
                }
                if (c2974c1.m1()) {
                    k0(sbU, 1, "uploading_gmp_version", Long.valueOf(c2974c1.g2()));
                }
                if (c2974c1.W0()) {
                    k0(sbU, 1, "dynamite_version", Long.valueOf(c2974c1.Y1()));
                }
                if (c2974c1.P0()) {
                    k0(sbU, 1, "config_version", Long.valueOf(c2974c1.W1()));
                }
                k0(sbU, 1, "gmp_app_id", c2974c1.B());
                k0(sbU, 1, "admob_app_id", c2974c1.q());
                k0(sbU, 1, "app_id", c2974c1.r());
                k0(sbU, 1, "app_version", c2974c1.u());
                if (c2974c1.K1()) {
                    k0(sbU, 1, "app_version_major", Integer.valueOf(c2974c1.M0()));
                }
                k0(sbU, 1, "firebase_instance_id", c2974c1.A());
                if (c2974c1.U0()) {
                    k0(sbU, 1, "dev_cert_hash", Long.valueOf(c2974c1.X1()));
                }
                k0(sbU, 1, "app_store", c2974c1.t());
                if (c2974c1.l1()) {
                    k0(sbU, 1, "upload_timestamp_millis", Long.valueOf(c2974c1.f2()));
                }
                if (c2974c1.i1()) {
                    k0(sbU, 1, "start_timestamp_millis", Long.valueOf(c2974c1.d2()));
                }
                if (c2974c1.X0()) {
                    k0(sbU, 1, "end_timestamp_millis", Long.valueOf(c2974c1.Z1()));
                }
                if (c2974c1.c1()) {
                    k0(sbU, 1, "previous_bundle_start_timestamp_millis", Long.valueOf(c2974c1.c2()));
                }
                if (c2974c1.b1()) {
                    k0(sbU, 1, "previous_bundle_end_timestamp_millis", Long.valueOf(c2974c1.b2()));
                }
                k0(sbU, 1, "app_instance_id", c2974c1.s());
                k0(sbU, 1, "resettable_device_id", c2974c1.F());
                k0(sbU, 1, "ds_id", c2974c1.z());
                if (c2974c1.a1()) {
                    k0(sbU, 1, "limited_ad_tracking", Boolean.valueOf(c2974c1.H1()));
                }
                k0(sbU, 1, "os_version", c2974c1.D());
                k0(sbU, 1, "device_model", c2974c1.y());
                k0(sbU, 1, "user_default_language", c2974c1.H());
                if (c2974c1.k1()) {
                    k0(sbU, 1, "time_zone_offset_minutes", Integer.valueOf(c2974c1.T1()));
                }
                if (c2974c1.O0()) {
                    k0(sbU, 1, "bundle_sequential_index", Integer.valueOf(c2974c1.M1()));
                }
                if (c2974c1.T0()) {
                    k0(sbU, 1, "delivery_index", Integer.valueOf(c2974c1.P1()));
                }
                if (c2974c1.f1()) {
                    k0(sbU, 1, "service_upload", Boolean.valueOf(c2974c1.I1()));
                }
                k0(sbU, 1, "health_monitor", c2974c1.C());
                if (c2974c1.e1()) {
                    k0(sbU, 1, "retry_counter", Integer.valueOf(c2974c1.S1()));
                }
                if (c2974c1.R0()) {
                    k0(sbU, 1, "consent_signals", c2974c1.w());
                }
                if (c2974c1.Z0()) {
                    k0(sbU, 1, "is_dma_region", Boolean.valueOf(c2974c1.G1()));
                }
                if (c2974c1.S0()) {
                    k0(sbU, 1, "core_platform_services", c2974c1.x());
                }
                if (c2974c1.Q0()) {
                    k0(sbU, 1, "consent_diagnostics", c2974c1.v());
                }
                if (c2974c1.j1()) {
                    k0(sbU, 1, "target_os_version", Long.valueOf(c2974c1.e2()));
                }
                E3.b();
                if (y.g.f0(c2974c1.r(), AbstractC3893t.V0)) {
                    k0(sbU, 1, "ad_services_version", Integer.valueOf(c2974c1.M()));
                    if (c2974c1.L1() && (o0I2 = c2974c1.i2()) != null) {
                        f0(sbU, 2);
                        sbU.append("attribution_eligibility_status {\n");
                        k0(sbU, 2, "eligible", Boolean.valueOf(o0I2.y()));
                        k0(sbU, 2, "no_access_adservices_attribution_permission", Boolean.valueOf(o0I2.A()));
                        k0(sbU, 2, "pre_r", Boolean.valueOf(o0I2.B()));
                        k0(sbU, 2, "r_extensions_too_old", Boolean.valueOf(o0I2.C()));
                        k0(sbU, 2, "adservices_extension_too_old", Boolean.valueOf(o0I2.x()));
                        k0(sbU, 2, "ad_storage_not_allowed", Boolean.valueOf(o0I2.w()));
                        k0(sbU, 2, "measurement_manager_disabled", Boolean.valueOf(o0I2.z()));
                        f0(sbU, 2);
                        sbU.append("}\n");
                    }
                }
                if (c2974c1.J1()) {
                    com.google.android.gms.internal.measurement.L0 l0H2 = c2974c1.h2();
                    f0(sbU, 2);
                    sbU.append("ad_campaign_info {\n");
                    if (l0H2.p()) {
                        k0(sbU, 2, "deep_link_gclid", l0H2.B());
                    }
                    if (l0H2.o()) {
                        k0(sbU, 2, "deep_link_gbraid", l0H2.A());
                    }
                    if (l0H2.n()) {
                        k0(sbU, 2, "deep_link_gad_source", l0H2.z());
                    }
                    if (l0H2.q()) {
                        k0(sbU, 2, "deep_link_session_millis", Long.valueOf(l0H2.v()));
                    }
                    if (l0H2.u()) {
                        k0(sbU, 2, "market_referrer_gclid", l0H2.E());
                    }
                    if (l0H2.t()) {
                        k0(sbU, 2, "market_referrer_gbraid", l0H2.D());
                    }
                    if (l0H2.s()) {
                        k0(sbU, 2, "market_referrer_gad_source", l0H2.C());
                    }
                    if (l0H2.r()) {
                        k0(sbU, 2, "market_referrer_click_millis", Long.valueOf(l0H2.w()));
                    }
                    f0(sbU, 2);
                    sbU.append("}\n");
                }
                if (c2974c1.N0()) {
                    k0(sbU, 1, "batching_timestamp_millis", Long.valueOf(c2974c1.V1()));
                }
                if (c2974c1.h1()) {
                    C3009j1 c3009j1O = c2974c1.o();
                    f0(sbU, 2);
                    sbU.append("sgtm_diagnostics {\n");
                    int iS = c3009j1O.s();
                    k0(sbU, 2, "upload_type", iS != 1 ? iS != 2 ? iS != 3 ? iS != 4 ? "SDK_SERVICE_UPLOAD" : "PACKAGE_SERVICE_UPLOAD" : "SDK_CLIENT_UPLOAD" : "GA_UPLOAD" : "UPLOAD_TYPE_UNKNOWN");
                    k0(sbU, 2, "client_upload_eligibility", AbstractC1642h.A(c3009j1O.o()));
                    int iR = c3009j1O.r();
                    k0(sbU, 2, "service_upload_eligibility", iR != 1 ? iR != 2 ? iR != 3 ? iR != 4 ? iR != 5 ? "NON_PLAY_MISSING_SGTM_SERVER_URL" : "MISSING_SGTM_PROXY_INFO" : "MISSING_SGTM_SETTINGS" : "NOT_IN_ROLLOUT" : "SERVICE_UPLOAD_ELIGIBLE" : "SERVICE_UPLOAD_ELIGIBILITY_UNKNOWN");
                    f0(sbU, 2);
                    sbU.append("}\n");
                }
                InterfaceC2975c2<C3019l1> interfaceC2975c2K = c2974c1.K();
                D d = y.m;
                if (interfaceC2975c2K != null) {
                    for (C3019l1 c3019l1 : interfaceC2975c2K) {
                        if (c3019l1 != null) {
                            f0(sbU, 2);
                            sbU.append("user_property {\n");
                            k0(sbU, 2, "set_timestamp_millis", c3019l1.F() ? Long.valueOf(c3019l1.q()) : null);
                            k0(sbU, 2, "name", d.f(c3019l1.s()));
                            k0(sbU, 2, "string_value", c3019l1.t());
                            k0(sbU, 2, "int_value", c3019l1.E() ? Long.valueOf(c3019l1.p()) : null);
                            k0(sbU, 2, "double_value", c3019l1.C() ? Double.valueOf(c3019l1.n()) : null);
                            f0(sbU, 2);
                            sbU.append("}\n");
                        }
                    }
                }
                InterfaceC2975c2<com.google.android.gms.internal.measurement.Q0> interfaceC2975c2I = c2974c1.I();
                if (interfaceC2975c2I != null) {
                    for (com.google.android.gms.internal.measurement.Q0 q0 : interfaceC2975c2I) {
                        if (q0 != null) {
                            f0(sbU, 2);
                            sbU.append("audience_membership {\n");
                            if (q0.w()) {
                                k0(sbU, 2, "audience_id", Integer.valueOf(q0.n()));
                            }
                            if (q0.x()) {
                                k0(sbU, 2, "new_audience", Boolean.valueOf(q0.v()));
                            }
                            j0(sbU, "current_data", q0.p());
                            if (q0.y()) {
                                j0(sbU, "previous_data", q0.q());
                            }
                            f0(sbU, 2);
                            sbU.append("}\n");
                        }
                    }
                }
                InterfaceC2975c2<com.google.android.gms.internal.measurement.U0> interfaceC2975c2J = c2974c1.J();
                if (interfaceC2975c2J != null) {
                    for (com.google.android.gms.internal.measurement.U0 u0 : interfaceC2975c2J) {
                        if (u0 != null) {
                            f0(sbU, 2);
                            sbU.append("event {\n");
                            k0(sbU, 2, "name", d.d(u0.t()));
                            if (u0.F()) {
                                k0(sbU, 2, "timestamp_millis", Long.valueOf(u0.q()));
                            }
                            if (u0.E()) {
                                k0(sbU, 2, "previous_timestamp_millis", Long.valueOf(u0.p()));
                            }
                            if (u0.D()) {
                                k0(sbU, 2, "count", Integer.valueOf(u0.n()));
                            }
                            if (u0.o() != 0) {
                                d0(sbU, 2, (InterfaceC2975c2) u0.u());
                            }
                            f0(sbU, 2);
                            sbU.append("}\n");
                        }
                    }
                }
                f0(sbU, 1);
                sbU.append("}\n");
            }
        }
        sbU.append("} // End-of-batch\n");
        return sbU.toString();
    }
}

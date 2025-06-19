package com.squareup.moshi;

import java.io.IOException;
import java.math.BigDecimal;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import okio.C5091h;
import okio.InterfaceC5093j;

/* loaded from: classes3.dex */
public final class u extends p {
    public static final Object h = new Object();
    public Object[] g;

    @Override // com.squareup.moshi.p
    public final String B() {
        o oVar = o.e;
        Map.Entry entry = (Map.Entry) s0(Map.Entry.class, oVar);
        Object key = entry.getKey();
        if (!(key instanceof String)) {
            throw p0(key, oVar);
        }
        String str = (String) key;
        this.g[this.a - 1] = entry.getValue();
        this.c[this.a - 2] = str;
        return str;
    }

    @Override // com.squareup.moshi.p
    public final void C() {
        s0(Void.class, o.i);
        r0();
    }

    @Override // com.squareup.moshi.p
    public final InterfaceC5093j D() throws IOException {
        Object objD0 = d0();
        C5091h c5091h = new C5091h();
        s sVar = new s(c5091h);
        try {
            sVar.j(objD0);
            sVar.close();
            return c5091h;
        } catch (Throwable th) {
            try {
                sVar.close();
            } catch (Throwable th2) {
                th.addSuppressed(th2);
            }
            throw th;
        }
    }

    @Override // com.squareup.moshi.p
    public final String P() {
        int i = this.a;
        Object obj = i != 0 ? this.g[i - 1] : null;
        if (obj instanceof String) {
            r0();
            return (String) obj;
        }
        if (obj instanceof Number) {
            r0();
            return obj.toString();
        }
        if (obj == h) {
            throw new IllegalStateException("JsonReader is closed");
        }
        throw p0(obj, o.f);
    }

    @Override // com.squareup.moshi.p
    public final o Q() {
        int i = this.a;
        if (i == 0) {
            return o.j;
        }
        Object obj = this.g[i - 1];
        if (obj instanceof t) {
            return ((t) obj).a;
        }
        if (obj instanceof List) {
            return o.a;
        }
        if (obj instanceof Map) {
            return o.c;
        }
        if (obj instanceof Map.Entry) {
            return o.e;
        }
        if (obj instanceof String) {
            return o.f;
        }
        if (obj instanceof Boolean) {
            return o.h;
        }
        if (obj instanceof Number) {
            return o.g;
        }
        if (obj == null) {
            return o.i;
        }
        if (obj == h) {
            throw new IllegalStateException("JsonReader is closed");
        }
        throw p0(obj, "a JSON value");
    }

    @Override // com.squareup.moshi.p
    public final p Y() {
        u uVar = new u(this);
        uVar.g = (Object[]) this.g.clone();
        for (int i = 0; i < uVar.a; i++) {
            Object[] objArr = uVar.g;
            Object obj = objArr[i];
            if (obj instanceof t) {
                t tVar = (t) obj;
                objArr[i] = new t(tVar.a, tVar.b, tVar.c);
            }
        }
        return uVar;
    }

    @Override // com.squareup.moshi.p
    public final void a() {
        List list = (List) s0(List.class, o.a);
        t tVar = new t(o.b, list.toArray(new Object[list.size()]), 0);
        Object[] objArr = this.g;
        int i = this.a;
        objArr[i - 1] = tVar;
        this.b[i - 1] = 1;
        this.d[i - 1] = 0;
        if (tVar.hasNext()) {
            q0(tVar.next());
        }
    }

    @Override // com.squareup.moshi.p
    public final void a0() {
        if (l()) {
            q0(B());
        }
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public final void close() {
        Arrays.fill(this.g, 0, this.a, (Object) null);
        this.g[0] = h;
        this.b[0] = 8;
        this.a = 1;
    }

    @Override // com.squareup.moshi.p
    public final void d() {
        Map map = (Map) s0(Map.class, o.c);
        t tVar = new t(o.d, map.entrySet().toArray(new Object[map.size()]), 0);
        Object[] objArr = this.g;
        int i = this.a;
        objArr[i - 1] = tVar;
        this.b[i - 1] = 3;
        if (tVar.hasNext()) {
            q0(tVar.next());
        }
    }

    @Override // com.squareup.moshi.p
    public final void f() {
        o oVar = o.b;
        t tVar = (t) s0(t.class, oVar);
        if (tVar.a != oVar || tVar.hasNext()) {
            throw p0(tVar, oVar);
        }
        r0();
    }

    @Override // com.squareup.moshi.p
    public final void i() {
        o oVar = o.d;
        t tVar = (t) s0(t.class, oVar);
        if (tVar.a != oVar || tVar.hasNext()) {
            throw p0(tVar, oVar);
        }
        this.c[this.a - 1] = null;
        r0();
    }

    @Override // com.squareup.moshi.p
    public final int k0(com.airbnb.lottie.parser.moshi.c cVar) {
        o oVar = o.e;
        Map.Entry entry = (Map.Entry) s0(Map.Entry.class, oVar);
        Object key = entry.getKey();
        if (!(key instanceof String)) {
            throw p0(key, oVar);
        }
        String str = (String) key;
        int length = cVar.a.length;
        for (int i = 0; i < length; i++) {
            if (cVar.a[i].equals(str)) {
                this.g[this.a - 1] = entry.getValue();
                this.c[this.a - 2] = str;
                return i;
            }
        }
        return -1;
    }

    @Override // com.squareup.moshi.p
    public final boolean l() {
        int i = this.a;
        if (i == 0) {
            return false;
        }
        Object obj = this.g[i - 1];
        return !(obj instanceof Iterator) || ((Iterator) obj).hasNext();
    }

    @Override // com.squareup.moshi.p
    public final int l0(com.airbnb.lottie.parser.moshi.c cVar) {
        int i = this.a;
        Object obj = i != 0 ? this.g[i - 1] : null;
        if (!(obj instanceof String)) {
            if (obj != h) {
                return -1;
            }
            throw new IllegalStateException("JsonReader is closed");
        }
        String str = (String) obj;
        int length = cVar.a.length;
        for (int i2 = 0; i2 < length; i2++) {
            if (cVar.a[i2].equals(str)) {
                r0();
                return i2;
            }
        }
        return -1;
    }

    @Override // com.squareup.moshi.p
    public final void m0() {
        if (!this.f) {
            this.g[this.a - 1] = ((Map.Entry) s0(Map.Entry.class, o.e)).getValue();
            this.c[this.a - 2] = "null";
        } else {
            o oVarQ = Q();
            B();
            throw new JsonDataException("Cannot skip unexpected " + oVarQ + " at " + j());
        }
    }

    @Override // com.squareup.moshi.p
    public final void n0() {
        if (this.f) {
            throw new JsonDataException("Cannot skip unexpected " + Q() + " at " + j());
        }
        int i = this.a;
        if (i > 1) {
            this.c[i - 2] = "null";
        }
        Object obj = i != 0 ? this.g[i - 1] : null;
        if (obj instanceof t) {
            throw new JsonDataException("Expected a value but was " + Q() + " at path " + j());
        }
        if (obj instanceof Map.Entry) {
            Object[] objArr = this.g;
            int i2 = i - 1;
            objArr[i2] = ((Map.Entry) objArr[i2]).getValue();
        } else {
            if (i > 0) {
                r0();
                return;
            }
            throw new JsonDataException("Expected a value but was " + Q() + " at path " + j());
        }
    }

    @Override // com.squareup.moshi.p
    public final boolean p() {
        Boolean bool = (Boolean) s0(Boolean.class, o.h);
        r0();
        return bool.booleanValue();
    }

    @Override // com.squareup.moshi.p
    public final double q() throws NumberFormatException, JsonEncodingException {
        double dDoubleValue;
        o oVar = o.g;
        Object objS0 = s0(Object.class, oVar);
        if (objS0 instanceof Number) {
            dDoubleValue = ((Number) objS0).doubleValue();
        } else {
            if (!(objS0 instanceof String)) {
                throw p0(objS0, oVar);
            }
            try {
                dDoubleValue = Double.parseDouble((String) objS0);
            } catch (NumberFormatException unused) {
                throw p0(objS0, oVar);
            }
        }
        if (this.e || !(Double.isNaN(dDoubleValue) || Double.isInfinite(dDoubleValue))) {
            r0();
            return dDoubleValue;
        }
        throw new JsonEncodingException("JSON forbids NaN and infinities: " + dDoubleValue + " at path " + j());
    }

    public final void q0(Object obj) {
        int i = this.a;
        if (i == this.g.length) {
            if (i == 256) {
                throw new JsonDataException("Nesting too deep at " + j());
            }
            int[] iArr = this.b;
            this.b = Arrays.copyOf(iArr, iArr.length * 2);
            String[] strArr = this.c;
            this.c = (String[]) Arrays.copyOf(strArr, strArr.length * 2);
            int[] iArr2 = this.d;
            this.d = Arrays.copyOf(iArr2, iArr2.length * 2);
            Object[] objArr = this.g;
            this.g = Arrays.copyOf(objArr, objArr.length * 2);
        }
        Object[] objArr2 = this.g;
        int i2 = this.a;
        this.a = i2 + 1;
        objArr2[i2] = obj;
    }

    @Override // com.squareup.moshi.p
    public final int r() throws NumberFormatException {
        int iIntValueExact;
        o oVar = o.g;
        Object objS0 = s0(Object.class, oVar);
        if (objS0 instanceof Number) {
            iIntValueExact = ((Number) objS0).intValue();
        } else {
            if (!(objS0 instanceof String)) {
                throw p0(objS0, oVar);
            }
            try {
                try {
                    iIntValueExact = Integer.parseInt((String) objS0);
                } catch (NumberFormatException unused) {
                    throw p0(objS0, oVar);
                }
            } catch (NumberFormatException unused2) {
                iIntValueExact = new BigDecimal((String) objS0).intValueExact();
            }
        }
        r0();
        return iIntValueExact;
    }

    public final void r0() {
        int i = this.a;
        int i2 = i - 1;
        this.a = i2;
        Object[] objArr = this.g;
        objArr[i2] = null;
        this.b[i2] = 0;
        if (i2 > 0) {
            int[] iArr = this.d;
            int i3 = i - 2;
            iArr[i3] = iArr[i3] + 1;
            Object obj = objArr[i - 2];
            if (obj instanceof Iterator) {
                Iterator it2 = (Iterator) obj;
                if (it2.hasNext()) {
                    q0(it2.next());
                }
            }
        }
    }

    public final Object s0(Class cls, o oVar) {
        int i = this.a;
        Object obj = i != 0 ? this.g[i - 1] : null;
        if (cls.isInstance(obj)) {
            return cls.cast(obj);
        }
        if (obj == null && oVar == o.i) {
            return null;
        }
        if (obj == h) {
            throw new IllegalStateException("JsonReader is closed");
        }
        throw p0(obj, oVar);
    }

    @Override // com.squareup.moshi.p
    public final long y() throws NumberFormatException {
        long jLongValueExact;
        o oVar = o.g;
        Object objS0 = s0(Object.class, oVar);
        if (objS0 instanceof Number) {
            jLongValueExact = ((Number) objS0).longValue();
        } else {
            if (!(objS0 instanceof String)) {
                throw p0(objS0, oVar);
            }
            try {
                try {
                    jLongValueExact = Long.parseLong((String) objS0);
                } catch (NumberFormatException unused) {
                    throw p0(objS0, oVar);
                }
            } catch (NumberFormatException unused2) {
                jLongValueExact = new BigDecimal((String) objS0).longValueExact();
            }
        }
        r0();
        return jLongValueExact;
    }
}

package com.squareup.moshi;

import java.io.Closeable;
import java.util.ArrayList;
import java.util.Arrays;
import okio.InterfaceC5093j;

/* loaded from: classes3.dex */
public abstract class p implements Closeable {
    public int a;
    public int[] b;
    public String[] c;
    public int[] d;
    public final boolean e;
    public boolean f;

    public p() {
        this.b = new int[32];
        this.c = new String[32];
        this.d = new int[32];
    }

    public abstract String B();

    public abstract void C();

    public abstract InterfaceC5093j D();

    public abstract String P();

    public abstract o Q();

    public abstract p Y();

    public abstract void a();

    public abstract void a0();

    public final void c0(int i) {
        int i2 = this.a;
        int[] iArr = this.b;
        if (i2 == iArr.length) {
            if (i2 == 256) {
                throw new JsonDataException("Nesting too deep at " + j());
            }
            this.b = Arrays.copyOf(iArr, iArr.length * 2);
            String[] strArr = this.c;
            this.c = (String[]) Arrays.copyOf(strArr, strArr.length * 2);
            int[] iArr2 = this.d;
            this.d = Arrays.copyOf(iArr2, iArr2.length * 2);
        }
        int[] iArr3 = this.b;
        int i3 = this.a;
        this.a = i3 + 1;
        iArr3[i3] = i;
    }

    public abstract void d();

    public final Object d0() {
        int iOrdinal = Q().ordinal();
        if (iOrdinal == 0) {
            ArrayList arrayList = new ArrayList();
            a();
            while (l()) {
                arrayList.add(d0());
            }
            f();
            return arrayList;
        }
        if (iOrdinal != 2) {
            if (iOrdinal == 5) {
                return P();
            }
            if (iOrdinal == 6) {
                return Double.valueOf(q());
            }
            if (iOrdinal == 7) {
                return Boolean.valueOf(p());
            }
            if (iOrdinal == 8) {
                C();
                return null;
            }
            throw new IllegalStateException("Expected a value but was " + Q() + " at path " + j());
        }
        A a = new A();
        d();
        while (l()) {
            String strB = B();
            Object objD0 = d0();
            Object objPut = a.put(strB, objD0);
            if (objPut != null) {
                StringBuilder sbY = android.support.v4.media.session.a.y("Map key '", strB, "' has multiple values at path ");
                sbY.append(j());
                sbY.append(": ");
                sbY.append(objPut);
                sbY.append(" and ");
                sbY.append(objD0);
                throw new JsonDataException(sbY.toString());
            }
        }
        i();
        return a;
    }

    public abstract void f();

    public abstract void i();

    public final String j() {
        return H.c(this.a, this.b, this.c, this.d);
    }

    public abstract int k0(com.airbnb.lottie.parser.moshi.c cVar);

    public abstract boolean l();

    public abstract int l0(com.airbnb.lottie.parser.moshi.c cVar);

    public abstract void m0();

    public abstract void n0();

    public final void o0(String str) throws JsonEncodingException {
        StringBuilder sbX = android.support.v4.media.session.a.x(str, " at path ");
        sbX.append(j());
        throw new JsonEncodingException(sbX.toString());
    }

    public abstract boolean p();

    public final JsonDataException p0(Object obj, Object obj2) {
        if (obj == null) {
            return new JsonDataException("Expected " + obj2 + " but was null at path " + j());
        }
        return new JsonDataException("Expected " + obj2 + " but was " + obj + ", a " + obj.getClass().getName() + ", at path " + j());
    }

    public abstract double q();

    public abstract int r();

    public abstract long y();

    public p(p pVar) {
        this.a = pVar.a;
        this.b = (int[]) pVar.b.clone();
        this.c = (String[]) pVar.c.clone();
        this.d = (int[]) pVar.d.clone();
        this.e = pVar.e;
        this.f = pVar.f;
    }
}

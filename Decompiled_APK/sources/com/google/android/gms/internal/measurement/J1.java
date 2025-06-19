package com.google.android.gms.internal.measurement;

import com.google.android.gms.ads.nonagon.signalgeneration.AbstractC1642h;
import java.io.IOException;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.RandomAccess;

/* loaded from: classes2.dex */
public abstract class J1 {
    protected int zza;

    public static void b(Iterable iterable, List list) {
        Charset charset = AbstractC2980d2.a;
        iterable.getClass();
        if (iterable instanceof InterfaceC2990f2) {
            List listZza = ((InterfaceC2990f2) iterable).zza();
            if (list != null) {
                throw new ClassCastException();
            }
            list.size();
            Iterator it2 = listZza.iterator();
            if (it2.hasNext()) {
                Object next = it2.next();
                next.getClass();
                if (next instanceof O1) {
                    throw null;
                }
                if (!(next instanceof byte[])) {
                    throw null;
                }
                byte[] bArr = (byte[]) next;
                O1.g(0, bArr, bArr.length);
                throw null;
            }
            return;
        }
        if (iterable instanceof InterfaceC3049r2) {
            list.addAll((Collection) iterable);
            return;
        }
        if (iterable instanceof Collection) {
            int size = ((Collection) iterable).size();
            if (list instanceof ArrayList) {
                ((ArrayList) list).ensureCapacity(list.size() + size);
            } else if (list instanceof C3059t2) {
                C3059t2 c3059t2 = (C3059t2) list;
                int i = ((C3059t2) list).c + size;
                int length = c3059t2.b.length;
                if (i > length) {
                    if (length != 0) {
                        while (length < i) {
                            length = AbstractC1642h.i(length, 3, 2, 1, 10);
                        }
                        c3059t2.b = Arrays.copyOf(c3059t2.b, length);
                    } else {
                        c3059t2.b = new Object[Math.max(i, 10)];
                    }
                }
            }
        }
        int size2 = list.size();
        if (!(iterable instanceof List) || !(iterable instanceof RandomAccess)) {
            for (Object obj : iterable) {
                if (obj == null) {
                    V1.b(size2, list);
                    throw null;
                }
                list.add(obj);
            }
            return;
        }
        List list2 = (List) iterable;
        int size3 = list2.size();
        for (int i2 = 0; i2 < size3; i2++) {
            Object obj2 = list2.get(i2);
            if (obj2 == null) {
                V1.b(size2, list);
                throw null;
            }
            list.add(obj2);
        }
    }

    public abstract int a(InterfaceC3069v2 interfaceC3069v2);

    public final byte[] c() {
        try {
            W1 w1 = (W1) this;
            int iD = w1.d();
            byte[] bArr = new byte[iD];
            P1 p1 = new P1(iD, bArr);
            InterfaceC3069v2 interfaceC3069v2A = C3054s2.c.a(w1.getClass());
            C3005i2 c3005i2 = p1.b;
            if (c3005i2 == null) {
                c3005i2 = new C3005i2(p1);
            }
            interfaceC3069v2A.d(w1, c3005i2);
            if (iD - p1.e == 0) {
                return bArr;
            }
            throw new IllegalStateException("Did not write as much data as expected.");
        } catch (IOException e) {
            throw new RuntimeException(android.support.v4.media.session.a.B("Serializing ", getClass().getName(), " to a byte array threw an IOException (should never happen)."), e);
        }
    }
}

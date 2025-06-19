package com.google.android.gms.internal.play_billing;

import com.google.android.gms.ads.nonagon.signalgeneration.AbstractC1642h;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.RandomAccess;

/* loaded from: classes2.dex */
public final class L0 extends AbstractC3787c1 {
    private static final L0 zzb;
    private InterfaceC3799g1 zzd = C3846w1.e;

    static {
        L0 l0 = new L0();
        zzb = l0;
        AbstractC3787c1.k(L0.class, l0);
    }

    public static K0 n() {
        return (K0) zzb.f();
    }

    public static void o(L0 l0, Iterable iterable) {
        InterfaceC3799g1 interfaceC3799g1 = l0.zzd;
        if (!((Q0) interfaceC3799g1).a) {
            int size = interfaceC3799g1.size();
            l0.zzd = interfaceC3799g1.f(size + size);
        }
        List list = l0.zzd;
        Charset charset = AbstractC3802h1.a;
        iterable.getClass();
        if (iterable instanceof InterfaceC3808j1) {
            List listZza = ((InterfaceC3808j1) iterable).zza();
            if (list != null) {
                throw new ClassCastException();
            }
            list.size();
            Iterator it2 = listZza.iterator();
            if (it2.hasNext()) {
                Object next = it2.next();
                next.getClass();
                if (next instanceof U0) {
                    throw null;
                }
                if (!(next instanceof byte[])) {
                    throw null;
                }
                byte[] bArr = (byte[]) next;
                U0.g(0, bArr, bArr.length);
                throw null;
            }
            return;
        }
        if (iterable instanceof InterfaceC3840u1) {
            list.addAll((Collection) iterable);
            return;
        }
        if (iterable instanceof Collection) {
            int size2 = ((Collection) iterable).size();
            if (list instanceof ArrayList) {
                ((ArrayList) list).ensureCapacity(list.size() + size2);
            }
            if (list instanceof C3846w1) {
                C3846w1 c3846w1 = (C3846w1) list;
                int i = ((C3846w1) list).c + size2;
                int length = c3846w1.b.length;
                if (i > length) {
                    if (length != 0) {
                        while (length < i) {
                            length = AbstractC1642h.i(length, 3, 2, 1, 10);
                        }
                        c3846w1.b = Arrays.copyOf(c3846w1.b, length);
                    } else {
                        c3846w1.b = new Object[Math.max(i, 10)];
                    }
                }
            }
        }
        int size3 = list.size();
        if (!(iterable instanceof List) || !(iterable instanceof RandomAccess)) {
            for (Object obj : iterable) {
                if (obj == null) {
                    AbstractC3784b1.b(size3, list);
                    throw null;
                }
                list.add(obj);
            }
            return;
        }
        List list2 = (List) iterable;
        int size4 = list2.size();
        for (int i2 = 0; i2 < size4; i2++) {
            Object obj2 = list2.get(i2);
            if (obj2 == null) {
                AbstractC3784b1.b(size3, list);
                throw null;
            }
            list.add(obj2);
        }
    }

    @Override // com.google.android.gms.internal.play_billing.AbstractC3787c1
    public final Object d(int i) {
        int i2 = i - 1;
        if (i2 == 0) {
            return (byte) 1;
        }
        if (i2 == 2) {
            return new C3849x1(zzb, "\u0004\u0001\u0000\u0000\u0001\u0001\u0001\u0000\u0001\u0000\u0001\u001b", new Object[]{"zzd", J0.class});
        }
        if (i2 == 3) {
            return new L0();
        }
        if (i2 == 4) {
            return new K0(zzb);
        }
        if (i2 != 5) {
            return null;
        }
        return zzb;
    }
}

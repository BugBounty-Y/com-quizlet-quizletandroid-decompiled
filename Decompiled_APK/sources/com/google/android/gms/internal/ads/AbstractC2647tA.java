package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;
import com.google.android.gms.ads.nonagon.signalgeneration.AbstractC1642h;
import java.io.IOException;
import java.nio.charset.Charset;
import java.util.AbstractCollection;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.RandomAccess;
import java.util.logging.Logger;

/* renamed from: com.google.android.gms.internal.ads.tA, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC2647tA {
    protected int zzq;

    /* JADX WARN: Multi-variable type inference failed */
    public static void c(AbstractCollection abstractCollection, List list) {
        Charset charset = WA.a;
        abstractCollection.getClass();
        if (abstractCollection instanceof InterfaceC2262kB) {
            list.addAll(abstractCollection);
            return;
        }
        int size = abstractCollection.size();
        if (list instanceof ArrayList) {
            ((ArrayList) list).ensureCapacity(list.size() + size);
        } else if (list instanceof C2348mB) {
            C2348mB c2348mB = (C2348mB) list;
            int i = ((C2348mB) list).c + size;
            int length = c2348mB.b.length;
            if (i > length) {
                if (length != 0) {
                    while (length < i) {
                        length = AbstractC1642h.i(length, 3, 2, 1, 10);
                    }
                    c2348mB.b = Arrays.copyOf(c2348mB.b, length);
                } else {
                    c2348mB.b = new Object[Math.max(i, 10)];
                }
            }
        }
        int size2 = list.size();
        if (!(abstractCollection instanceof List) || !(abstractCollection instanceof RandomAccess)) {
            for (Object obj : abstractCollection) {
                if (obj == null) {
                    MA.f(size2, list);
                    throw null;
                }
                list.add(obj);
            }
            return;
        }
        List list2 = (List) abstractCollection;
        int size3 = list2.size();
        for (int i2 = 0; i2 < size3; i2++) {
            Object obj2 = list2.get(i2);
            if (obj2 == null) {
                MA.f(size2, list);
                throw null;
            }
            list.add(obj2);
        }
    }

    public abstract int a(InterfaceC2562rB interfaceC2562rB);

    public final C2905zA b() {
        try {
            int iA = ((OA) this).a(null);
            C2905zA c2905zA = BA.b;
            byte[] bArr = new byte[iA];
            Logger logger = HA.c;
            FA fa = new FA(iA, bArr);
            ((OA) this).q(fa);
            if (iA - fa.g == 0) {
                return new C2905zA(bArr);
            }
            throw new IllegalStateException("Did not write as much data as expected.");
        } catch (IOException e) {
            throw new RuntimeException(e("ByteString"), e);
        }
    }

    public final byte[] d() {
        try {
            int iA = ((OA) this).a(null);
            byte[] bArr = new byte[iA];
            Logger logger = HA.c;
            FA fa = new FA(iA, bArr);
            ((OA) this).q(fa);
            if (iA - fa.g == 0) {
                return bArr;
            }
            throw new IllegalStateException("Did not write as much data as expected.");
        } catch (IOException e) {
            throw new RuntimeException(e("byte array"), e);
        }
    }

    public final String e(String str) {
        return AbstractC0147y.e("Serializing ", getClass().getName(), " to a ", str, " threw an IOException (should never happen).");
    }
}

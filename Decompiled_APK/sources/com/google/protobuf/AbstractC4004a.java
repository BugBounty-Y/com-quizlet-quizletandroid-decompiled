package com.google.protobuf;

import java.io.OutputStream;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

/* renamed from: com.google.protobuf.a, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC4004a {
    protected int memoizedHashCode;

    public static void a(List list, List list2) {
        Charset charset = C.a;
        list.getClass();
        if (list instanceof F) {
            List listL = ((F) list).l();
            F f = (F) list2;
            int size = list2.size();
            for (Object obj : listL) {
                if (obj == null) {
                    String str = "Element at index " + (f.size() - size) + " is null.";
                    for (int size2 = f.size() - 1; size2 >= size; size2--) {
                        f.remove(size2);
                    }
                    throw new NullPointerException(str);
                }
                if (obj instanceof C4012f) {
                    f.p((C4012f) obj);
                } else {
                    f.add((String) obj);
                }
            }
            return;
        }
        if (list instanceof Y) {
            list2.addAll(list);
            return;
        }
        if (list2 instanceof ArrayList) {
            ((ArrayList) list2).ensureCapacity(list.size() + list2.size());
        }
        int size3 = list2.size();
        for (Object obj2 : list) {
            if (obj2 == null) {
                String str2 = "Element at index " + (list2.size() - size3) + " is null.";
                for (int size4 = list2.size() - 1; size4 >= size3; size4--) {
                    list2.remove(size4);
                }
                throw new NullPointerException(str2);
            }
            list2.add(obj2);
        }
    }

    public abstract int h(InterfaceC4009c0 interfaceC4009c0);

    public abstract void i(AbstractC4018l abstractC4018l);

    public final void j(OutputStream outputStream) {
        int iH = ((AbstractC4027v) this).h(null);
        Logger logger = AbstractC4018l.d;
        if (iH > 4096) {
            iH = 4096;
        }
        C4017k c4017k = new C4017k(outputStream, iH);
        i(c4017k);
        if (c4017k.h > 0) {
            c4017k.M();
        }
    }
}

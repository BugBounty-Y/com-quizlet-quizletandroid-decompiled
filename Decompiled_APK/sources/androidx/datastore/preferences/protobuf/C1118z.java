package androidx.datastore.preferences.protobuf;

/* renamed from: androidx.datastore.preferences.protobuf.z, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1118z {
    public static InterfaceC1114v a(long j, Object obj) {
        InterfaceC1114v interfaceC1114v = (InterfaceC1114v) g0.c.h(j, obj);
        if (((AbstractC1095b) interfaceC1114v).a) {
            return interfaceC1114v;
        }
        S s = (S) interfaceC1114v;
        int i = s.c;
        S sC = s.c(i == 0 ? 10 : i * 2);
        g0.o(j, obj, sC);
        return sC;
    }
}

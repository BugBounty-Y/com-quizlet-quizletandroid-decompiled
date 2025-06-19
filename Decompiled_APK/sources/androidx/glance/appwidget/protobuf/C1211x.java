package androidx.glance.appwidget.protobuf;

/* renamed from: androidx.glance.appwidget.protobuf.x, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1211x {
    public static InterfaceC1208u a(long j, Object obj) {
        InterfaceC1208u interfaceC1208u = (InterfaceC1208u) Y.c.h(j, obj);
        if (((AbstractC1190b) interfaceC1208u).a) {
            return interfaceC1208u;
        }
        M m = (M) interfaceC1208u;
        int i = m.c;
        M mC = m.c(i == 0 ? 10 : i * 2);
        Y.o(j, obj, mC);
        return mC;
    }
}

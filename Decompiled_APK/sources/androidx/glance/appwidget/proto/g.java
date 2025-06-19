package androidx.glance.appwidget.proto;

import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.glance.appwidget.protobuf.AbstractC1205q;
import androidx.glance.appwidget.protobuf.AbstractC1206s;
import androidx.glance.appwidget.protobuf.K;
import androidx.glance.appwidget.protobuf.N;
import androidx.glance.appwidget.protobuf.r;

/* loaded from: classes.dex */
public final class g extends AbstractC1206s {
    private static final g DEFAULT_INSTANCE;
    public static final int LAYOUT_FIELD_NUMBER = 1;
    public static final int LAYOUT_INDEX_FIELD_NUMBER = 2;
    private static volatile K PARSER;
    private int bitField0_;
    private int layoutIndex_;
    private i layout_;

    static {
        g gVar = new g();
        DEFAULT_INSTANCE = gVar;
        AbstractC1206s.i(g.class, gVar);
    }

    public static void k(g gVar, i iVar) {
        gVar.getClass();
        iVar.getClass();
        gVar.layout_ = iVar;
        gVar.bitField0_ |= 1;
    }

    public static void l(g gVar, int i) {
        gVar.layoutIndex_ = i;
    }

    public static f o() {
        return (f) ((AbstractC1205q) DEFAULT_INSTANCE.b(5));
    }

    @Override // androidx.glance.appwidget.protobuf.AbstractC1206s
    public final Object b(int i) {
        K rVar;
        switch (AbstractC0147y.k(i)) {
            case 0:
                return (byte) 1;
            case 1:
                return null;
            case 2:
                return new N(DEFAULT_INSTANCE, "\u0000\u0002\u0000\u0001\u0001\u0002\u0002\u0000\u0000\u0000\u0001ဉ\u0000\u0002\u0004", new Object[]{"bitField0_", "layout_", "layoutIndex_"});
            case 3:
                return new g();
            case 4:
                return new f(DEFAULT_INSTANCE);
            case 5:
                return DEFAULT_INSTANCE;
            case 6:
                K k = PARSER;
                if (k != null) {
                    return k;
                }
                synchronized (g.class) {
                    try {
                        rVar = PARSER;
                        if (rVar == null) {
                            rVar = new r();
                            PARSER = rVar;
                        }
                    } catch (Throwable th) {
                        throw th;
                    }
                }
                return rVar;
            default:
                throw new UnsupportedOperationException();
        }
    }

    public final i m() {
        i iVar = this.layout_;
        return iVar == null ? i.v() : iVar;
    }

    public final int n() {
        return this.layoutIndex_;
    }
}

package androidx.glance.appwidget.protobuf;

import sun.misc.Unsafe;

/* loaded from: classes.dex */
public final class V extends X {
    public final /* synthetic */ int b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ V(Unsafe unsafe, int i) {
        super(unsafe);
        this.b = i;
    }

    @Override // androidx.glance.appwidget.protobuf.X
    public final boolean c(long j, Object obj) {
        switch (this.b) {
            case 0:
                if (!Y.g) {
                    break;
                } else {
                    break;
                }
            default:
                if (!Y.g) {
                    break;
                } else {
                    break;
                }
        }
        return Y.c(j, obj);
    }

    @Override // androidx.glance.appwidget.protobuf.X
    public final double d(long j, Object obj) {
        switch (this.b) {
        }
        return Double.longBitsToDouble(g(j, obj));
    }

    @Override // androidx.glance.appwidget.protobuf.X
    public final float e(long j, Object obj) {
        switch (this.b) {
        }
        return Float.intBitsToFloat(f(j, obj));
    }

    @Override // androidx.glance.appwidget.protobuf.X
    public final void j(Object obj, long j, boolean z) {
        switch (this.b) {
            case 0:
                if (!Y.g) {
                    Y.l(obj, j, z ? (byte) 1 : (byte) 0);
                    break;
                } else {
                    Y.k(obj, j, z ? (byte) 1 : (byte) 0);
                    break;
                }
            default:
                if (!Y.g) {
                    Y.l(obj, j, z ? (byte) 1 : (byte) 0);
                    break;
                } else {
                    Y.k(obj, j, z ? (byte) 1 : (byte) 0);
                    break;
                }
        }
    }

    @Override // androidx.glance.appwidget.protobuf.X
    public final void k(Object obj, long j, byte b) {
        switch (this.b) {
            case 0:
                if (!Y.g) {
                    Y.l(obj, j, b);
                    break;
                } else {
                    Y.k(obj, j, b);
                    break;
                }
            default:
                if (!Y.g) {
                    Y.l(obj, j, b);
                    break;
                } else {
                    Y.k(obj, j, b);
                    break;
                }
        }
    }

    @Override // androidx.glance.appwidget.protobuf.X
    public final void l(Object obj, long j, double d) {
        switch (this.b) {
            case 0:
                o(obj, j, Double.doubleToLongBits(d));
                break;
            default:
                o(obj, j, Double.doubleToLongBits(d));
                break;
        }
    }

    @Override // androidx.glance.appwidget.protobuf.X
    public final void m(Object obj, long j, float f) {
        switch (this.b) {
            case 0:
                n(j, obj, Float.floatToIntBits(f));
                break;
            default:
                n(j, obj, Float.floatToIntBits(f));
                break;
        }
    }

    @Override // androidx.glance.appwidget.protobuf.X
    public final boolean r() {
        switch (this.b) {
        }
        return false;
    }
}

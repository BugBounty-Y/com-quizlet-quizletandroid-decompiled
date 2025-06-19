package androidx.datastore.preferences.protobuf;

import sun.misc.Unsafe;

/* loaded from: classes.dex */
public final class d0 extends f0 {
    public final /* synthetic */ int b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ d0(Unsafe unsafe, int i) {
        super(unsafe);
        this.b = i;
    }

    @Override // androidx.datastore.preferences.protobuf.f0
    public final boolean c(long j, Object obj) {
        switch (this.b) {
            case 0:
                if (!g0.g) {
                    break;
                } else {
                    break;
                }
            default:
                if (!g0.g) {
                    break;
                } else {
                    break;
                }
        }
        return g0.c(j, obj);
    }

    @Override // androidx.datastore.preferences.protobuf.f0
    public final double d(long j, Object obj) {
        switch (this.b) {
        }
        return Double.longBitsToDouble(g(j, obj));
    }

    @Override // androidx.datastore.preferences.protobuf.f0
    public final float e(long j, Object obj) {
        switch (this.b) {
        }
        return Float.intBitsToFloat(f(j, obj));
    }

    @Override // androidx.datastore.preferences.protobuf.f0
    public final void j(Object obj, long j, boolean z) {
        switch (this.b) {
            case 0:
                if (!g0.g) {
                    g0.l(obj, j, z ? (byte) 1 : (byte) 0);
                    break;
                } else {
                    g0.k(obj, j, z ? (byte) 1 : (byte) 0);
                    break;
                }
            default:
                if (!g0.g) {
                    g0.l(obj, j, z ? (byte) 1 : (byte) 0);
                    break;
                } else {
                    g0.k(obj, j, z ? (byte) 1 : (byte) 0);
                    break;
                }
        }
    }

    @Override // androidx.datastore.preferences.protobuf.f0
    public final void k(Object obj, long j, byte b) {
        switch (this.b) {
            case 0:
                if (!g0.g) {
                    g0.l(obj, j, b);
                    break;
                } else {
                    g0.k(obj, j, b);
                    break;
                }
            default:
                if (!g0.g) {
                    g0.l(obj, j, b);
                    break;
                } else {
                    g0.k(obj, j, b);
                    break;
                }
        }
    }

    @Override // androidx.datastore.preferences.protobuf.f0
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

    @Override // androidx.datastore.preferences.protobuf.f0
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

    @Override // androidx.datastore.preferences.protobuf.f0
    public final boolean r() {
        switch (this.b) {
        }
        return false;
    }
}

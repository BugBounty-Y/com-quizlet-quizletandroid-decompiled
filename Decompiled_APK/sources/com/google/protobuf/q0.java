package com.google.protobuf;

import sun.misc.Unsafe;

/* loaded from: classes2.dex */
public final class q0 extends s0 {
    public final /* synthetic */ int b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ q0(Unsafe unsafe, int i) {
        super(unsafe);
        this.b = i;
    }

    @Override // com.google.protobuf.s0
    public final boolean c(long j, Object obj) {
        switch (this.b) {
            case 0:
                if (t0.g) {
                    if (t0.h(j, obj) == 0) {
                    }
                } else if (t0.i(j, obj) == 0) {
                }
                break;
            default:
                if (t0.g) {
                    if (t0.h(j, obj) == 0) {
                    }
                } else if (t0.i(j, obj) == 0) {
                }
                break;
        }
        return false;
    }

    @Override // com.google.protobuf.s0
    public final byte d(long j, Object obj) {
        switch (this.b) {
            case 0:
                if (!t0.g) {
                    break;
                } else {
                    break;
                }
            default:
                if (!t0.g) {
                    break;
                } else {
                    break;
                }
        }
        return t0.i(j, obj);
    }

    @Override // com.google.protobuf.s0
    public final double e(long j, Object obj) {
        switch (this.b) {
        }
        return Double.longBitsToDouble(h(j, obj));
    }

    @Override // com.google.protobuf.s0
    public final float f(long j, Object obj) {
        switch (this.b) {
        }
        return Float.intBitsToFloat(g(j, obj));
    }

    @Override // com.google.protobuf.s0
    public final void k(Object obj, long j, boolean z) {
        switch (this.b) {
            case 0:
                if (!t0.g) {
                    t0.m(obj, j, z ? (byte) 1 : (byte) 0);
                    break;
                } else {
                    t0.l(obj, j, z ? (byte) 1 : (byte) 0);
                    break;
                }
            default:
                if (!t0.g) {
                    t0.m(obj, j, z ? (byte) 1 : (byte) 0);
                    break;
                } else {
                    t0.l(obj, j, z ? (byte) 1 : (byte) 0);
                    break;
                }
        }
    }

    @Override // com.google.protobuf.s0
    public final void l(Object obj, long j, byte b) {
        switch (this.b) {
            case 0:
                if (!t0.g) {
                    t0.m(obj, j, b);
                    break;
                } else {
                    t0.l(obj, j, b);
                    break;
                }
            default:
                if (!t0.g) {
                    t0.m(obj, j, b);
                    break;
                } else {
                    t0.l(obj, j, b);
                    break;
                }
        }
    }

    @Override // com.google.protobuf.s0
    public final void m(Object obj, long j, double d) {
        switch (this.b) {
            case 0:
                p(obj, j, Double.doubleToLongBits(d));
                break;
            default:
                p(obj, j, Double.doubleToLongBits(d));
                break;
        }
    }

    @Override // com.google.protobuf.s0
    public final void n(Object obj, long j, float f) {
        switch (this.b) {
            case 0:
                o(j, obj, Float.floatToIntBits(f));
                break;
            default:
                o(j, obj, Float.floatToIntBits(f));
                break;
        }
    }

    @Override // com.google.protobuf.s0
    public final boolean s() {
        switch (this.b) {
        }
        return false;
    }
}

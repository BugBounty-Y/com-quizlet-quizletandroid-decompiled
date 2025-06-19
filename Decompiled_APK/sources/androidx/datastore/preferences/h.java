package androidx.datastore.preferences;

import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.datastore.preferences.protobuf.AbstractC1111s;
import androidx.datastore.preferences.protobuf.AbstractC1113u;
import androidx.datastore.preferences.protobuf.C1100g;
import androidx.datastore.preferences.protobuf.C1112t;
import androidx.datastore.preferences.protobuf.O;
import androidx.datastore.preferences.protobuf.T;
import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes.dex */
public final class h extends AbstractC1113u {
    public static final int BOOLEAN_FIELD_NUMBER = 1;
    public static final int BYTES_FIELD_NUMBER = 8;
    private static final h DEFAULT_INSTANCE;
    public static final int DOUBLE_FIELD_NUMBER = 7;
    public static final int FLOAT_FIELD_NUMBER = 2;
    public static final int INTEGER_FIELD_NUMBER = 3;
    public static final int LONG_FIELD_NUMBER = 4;
    private static volatile O PARSER = null;
    public static final int STRING_FIELD_NUMBER = 5;
    public static final int STRING_SET_FIELD_NUMBER = 6;
    private int valueCase_ = 0;
    private Object value_;

    static {
        h hVar = new h();
        DEFAULT_INSTANCE = hVar;
        AbstractC1113u.j(h.class, hVar);
    }

    public static g D() {
        return (g) ((AbstractC1111s) DEFAULT_INSTANCE.c(5));
    }

    public static void l(h hVar, long j) {
        hVar.valueCase_ = 4;
        hVar.value_ = Long.valueOf(j);
    }

    public static void m(h hVar, String str) {
        hVar.getClass();
        str.getClass();
        hVar.valueCase_ = 5;
        hVar.value_ = str;
    }

    public static void n(h hVar, f fVar) {
        hVar.getClass();
        hVar.value_ = fVar;
        hVar.valueCase_ = 6;
    }

    public static void o(h hVar, double d) {
        hVar.valueCase_ = 7;
        hVar.value_ = Double.valueOf(d);
    }

    public static void p(h hVar, C1100g c1100g) {
        hVar.getClass();
        hVar.valueCase_ = 8;
        hVar.value_ = c1100g;
    }

    public static void q(h hVar, boolean z) {
        hVar.valueCase_ = 1;
        hVar.value_ = Boolean.valueOf(z);
    }

    public static void r(h hVar, float f) {
        hVar.valueCase_ = 2;
        hVar.value_ = Float.valueOf(f);
    }

    public static void s(h hVar, int i) {
        hVar.valueCase_ = 3;
        hVar.value_ = Integer.valueOf(i);
    }

    public static h v() {
        return DEFAULT_INSTANCE;
    }

    public final String A() {
        return this.valueCase_ == 5 ? (String) this.value_ : "";
    }

    public final f B() {
        return this.valueCase_ == 6 ? (f) this.value_ : f.m();
    }

    public final int C() {
        switch (this.valueCase_) {
            case 0:
                return 9;
            case 1:
                return 1;
            case 2:
                return 2;
            case 3:
                return 3;
            case 4:
                return 4;
            case 5:
                return 5;
            case 6:
                return 6;
            case 7:
                return 7;
            case 8:
                return 8;
            default:
                return 0;
        }
    }

    @Override // androidx.datastore.preferences.protobuf.AbstractC1113u
    public final Object c(int i) {
        O c1112t;
        switch (AbstractC0147y.k(i)) {
            case 0:
                return (byte) 1;
            case 1:
                return null;
            case 2:
                return new T(DEFAULT_INSTANCE, "\u0001\b\u0001\u0000\u0001\b\b\u0000\u0000\u0000\u0001:\u0000\u00024\u0000\u00037\u0000\u00045\u0000\u0005;\u0000\u0006<\u0000\u00073\u0000\b=\u0000", new Object[]{"value_", "valueCase_", f.class});
            case 3:
                return new h();
            case 4:
                return new g(DEFAULT_INSTANCE);
            case 5:
                return DEFAULT_INSTANCE;
            case 6:
                O o = PARSER;
                if (o != null) {
                    return o;
                }
                synchronized (h.class) {
                    try {
                        c1112t = PARSER;
                        if (c1112t == null) {
                            c1112t = new C1112t();
                            PARSER = c1112t;
                        }
                    } catch (Throwable th) {
                        throw th;
                    }
                }
                return c1112t;
            default:
                throw new UnsupportedOperationException();
        }
    }

    public final boolean t() {
        if (this.valueCase_ == 1) {
            return ((Boolean) this.value_).booleanValue();
        }
        return false;
    }

    public final C1100g u() {
        return this.valueCase_ == 8 ? (C1100g) this.value_ : C1100g.c;
    }

    public final double w() {
        if (this.valueCase_ == 7) {
            return ((Double) this.value_).doubleValue();
        }
        return 0.0d;
    }

    public final float x() {
        return this.valueCase_ == 2 ? ((Float) this.value_).floatValue() : DefinitionKt.NO_Float_VALUE;
    }

    public final int y() {
        if (this.valueCase_ == 3) {
            return ((Integer) this.value_).intValue();
        }
        return 0;
    }

    public final long z() {
        if (this.valueCase_ == 4) {
            return ((Long) this.value_).longValue();
        }
        return 0L;
    }
}

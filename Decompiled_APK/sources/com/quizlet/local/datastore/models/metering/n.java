package com.quizlet.local.datastore.models.metering;

import androidx.camera.camera2.internal.AbstractC0147y;
import com.google.protobuf.AbstractC4027v;
import com.google.protobuf.C4007b0;
import com.google.protobuf.C4026u;
import com.google.protobuf.N;
import com.google.protobuf.X;
import java.io.InputStream;

/* loaded from: classes3.dex */
public final class n extends AbstractC4027v {
    public static final int DATA_FIELD_NUMBER = 1;
    private static final n DEFAULT_INSTANCE;
    private static volatile X PARSER;
    private N data_ = N.b;

    static {
        n nVar = new n();
        DEFAULT_INSTANCE = nVar;
        AbstractC4027v.u(n.class, nVar);
    }

    public static N w(n nVar) {
        N n = nVar.data_;
        if (!n.a) {
            nVar.data_ = n.e();
        }
        return nVar.data_;
    }

    public static n y() {
        return DEFAULT_INSTANCE;
    }

    public static n z(InputStream inputStream) {
        return (n) AbstractC4027v.t(DEFAULT_INSTANCE, inputStream);
    }

    @Override // com.google.protobuf.AbstractC4027v
    public final Object l(int i) {
        X c4026u;
        switch (AbstractC0147y.k(i)) {
            case 0:
                return (byte) 1;
            case 1:
                return null;
            case 2:
                return new C4007b0(DEFAULT_INSTANCE, "\u0000\u0001\u0000\u0000\u0001\u0001\u0001\u0001\u0000\u0000\u00012", new Object[]{"data_", m.a});
            case 3:
                return new n();
            case 4:
                return new l(DEFAULT_INSTANCE);
            case 5:
                return DEFAULT_INSTANCE;
            case 6:
                X x = PARSER;
                if (x != null) {
                    return x;
                }
                synchronized (n.class) {
                    try {
                        c4026u = PARSER;
                        if (c4026u == null) {
                            c4026u = new C4026u();
                            PARSER = c4026u;
                        }
                    } catch (Throwable th) {
                        throw th;
                    }
                }
                return c4026u;
            default:
                throw new UnsupportedOperationException();
        }
    }

    public final d x(String str) {
        str.getClass();
        N n = this.data_;
        if (n.containsKey(str)) {
            return (d) n.get(str);
        }
        throw new IllegalArgumentException();
    }
}

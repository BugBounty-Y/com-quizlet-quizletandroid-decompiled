package androidx.datastore.preferences;

import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.core.view.AbstractC1047f0;
import androidx.datastore.preferences.protobuf.AbstractC1111s;
import androidx.datastore.preferences.protobuf.AbstractC1113u;
import androidx.datastore.preferences.protobuf.AbstractC1115w;
import androidx.datastore.preferences.protobuf.C1101h;
import androidx.datastore.preferences.protobuf.C1102i;
import androidx.datastore.preferences.protobuf.C1103j;
import androidx.datastore.preferences.protobuf.C1106m;
import androidx.datastore.preferences.protobuf.C1112t;
import androidx.datastore.preferences.protobuf.F;
import androidx.datastore.preferences.protobuf.InvalidProtocolBufferException;
import androidx.datastore.preferences.protobuf.O;
import androidx.datastore.preferences.protobuf.Q;
import androidx.datastore.preferences.protobuf.T;
import androidx.datastore.preferences.protobuf.U;
import androidx.datastore.preferences.protobuf.UninitializedMessageException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;
import java.util.Map;

/* loaded from: classes.dex */
public final class d extends AbstractC1113u {
    private static final d DEFAULT_INSTANCE;
    private static volatile O PARSER = null;
    public static final int PREFERENCES_FIELD_NUMBER = 1;
    private F preferences_ = F.b;

    static {
        d dVar = new d();
        DEFAULT_INSTANCE = dVar;
        AbstractC1113u.j(d.class, dVar);
    }

    public static F l(d dVar) {
        F f = dVar.preferences_;
        if (!f.a) {
            dVar.preferences_ = f.d();
        }
        return dVar.preferences_;
    }

    public static b n() {
        return (b) ((AbstractC1111s) DEFAULT_INSTANCE.c(5));
    }

    public static d o(InputStream inputStream) {
        AbstractC1047f0 c1102i;
        d dVar = DEFAULT_INSTANCE;
        if (inputStream == null) {
            byte[] bArr = AbstractC1115w.b;
            int length = bArr.length;
            c1102i = new C1101h(bArr, 0, length, false);
            try {
                c1102i.i(length);
            } catch (InvalidProtocolBufferException e) {
                throw new IllegalArgumentException(e);
            }
        } else {
            c1102i = new C1102i(inputStream);
        }
        C1106m c1106mA = C1106m.a();
        AbstractC1113u abstractC1113uI = dVar.i();
        try {
            Q q = Q.c;
            q.getClass();
            U uA = q.a(abstractC1113uI.getClass());
            C1103j c1103j = (C1103j) c1102i.b;
            if (c1103j == null) {
                c1103j = new C1103j(c1102i);
            }
            uA.i(abstractC1113uI, c1103j, c1106mA);
            uA.b(abstractC1113uI);
            if (AbstractC1113u.f(abstractC1113uI, true)) {
                return (d) abstractC1113uI;
            }
            throw new InvalidProtocolBufferException(new UninitializedMessageException().getMessage());
        } catch (InvalidProtocolBufferException e2) {
            if (e2.a) {
                throw new InvalidProtocolBufferException(e2.getMessage(), e2);
            }
            throw e2;
        } catch (UninitializedMessageException e3) {
            throw new InvalidProtocolBufferException(e3.getMessage());
        } catch (IOException e4) {
            if (e4.getCause() instanceof InvalidProtocolBufferException) {
                throw ((InvalidProtocolBufferException) e4.getCause());
            }
            throw new InvalidProtocolBufferException(e4.getMessage(), e4);
        } catch (RuntimeException e5) {
            if (e5.getCause() instanceof InvalidProtocolBufferException) {
                throw ((InvalidProtocolBufferException) e5.getCause());
            }
            throw e5;
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
                return new T(DEFAULT_INSTANCE, "\u0001\u0001\u0000\u0000\u0001\u0001\u0001\u0001\u0000\u0000\u00012", new Object[]{"preferences_", c.a});
            case 3:
                return new d();
            case 4:
                return new b(DEFAULT_INSTANCE);
            case 5:
                return DEFAULT_INSTANCE;
            case 6:
                O o = PARSER;
                if (o != null) {
                    return o;
                }
                synchronized (d.class) {
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

    public final Map m() {
        return Collections.unmodifiableMap(this.preferences_);
    }
}

package androidx.datastore.preferences;

import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.datastore.preferences.protobuf.AbstractC1095b;
import androidx.datastore.preferences.protobuf.AbstractC1111s;
import androidx.datastore.preferences.protobuf.AbstractC1113u;
import androidx.datastore.preferences.protobuf.AbstractC1115w;
import androidx.datastore.preferences.protobuf.C1100g;
import androidx.datastore.preferences.protobuf.C1112t;
import androidx.datastore.preferences.protobuf.InterfaceC1114v;
import androidx.datastore.preferences.protobuf.InterfaceC1117y;
import androidx.datastore.preferences.protobuf.O;
import androidx.datastore.preferences.protobuf.P;
import androidx.datastore.preferences.protobuf.S;
import androidx.datastore.preferences.protobuf.T;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.RandomAccess;

/* loaded from: classes.dex */
public final class f extends AbstractC1113u {
    private static final f DEFAULT_INSTANCE;
    private static volatile O PARSER = null;
    public static final int STRINGS_FIELD_NUMBER = 1;
    private InterfaceC1114v strings_ = S.d;

    static {
        f fVar = new f();
        DEFAULT_INSTANCE = fVar;
        AbstractC1113u.j(f.class, fVar);
    }

    public static void l(f fVar, Iterable iterable) {
        InterfaceC1114v interfaceC1114v = fVar.strings_;
        if (!((AbstractC1095b) interfaceC1114v).a) {
            S s = (S) interfaceC1114v;
            int i = s.c;
            fVar.strings_ = s.c(i == 0 ? 10 : i * 2);
        }
        RandomAccess randomAccess = fVar.strings_;
        Charset charset = AbstractC1115w.a;
        iterable.getClass();
        if (iterable instanceof InterfaceC1117y) {
            List listL = ((InterfaceC1117y) iterable).l();
            if (randomAccess != null) {
                throw new ClassCastException();
            }
            ((S) randomAccess).getClass();
            Iterator it2 = listL.iterator();
            if (it2.hasNext()) {
                Object next = it2.next();
                next.getClass();
                if (next instanceof C1100g) {
                    throw null;
                }
                if (!(next instanceof byte[])) {
                    throw null;
                }
                byte[] bArr = (byte[]) next;
                C1100g.c(0, bArr, bArr.length);
                throw null;
            }
            return;
        }
        if (iterable instanceof P) {
            ((AbstractC1095b) randomAccess).addAll((Collection) iterable);
            return;
        }
        if ((randomAccess instanceof ArrayList) && (iterable instanceof Collection)) {
            ((ArrayList) randomAccess).ensureCapacity(((Collection) iterable).size() + ((S) randomAccess).c);
        }
        S s2 = (S) randomAccess;
        int i2 = s2.c;
        for (Object obj : iterable) {
            if (obj == null) {
                String str = "Element at index " + (s2.c - i2) + " is null.";
                for (int i3 = s2.c - 1; i3 >= i2; i3--) {
                    s2.remove(i3);
                }
                throw new NullPointerException(str);
            }
            s2.add(obj);
        }
    }

    public static f m() {
        return DEFAULT_INSTANCE;
    }

    public static e o() {
        return (e) ((AbstractC1111s) DEFAULT_INSTANCE.c(5));
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
                return new T(DEFAULT_INSTANCE, "\u0001\u0001\u0000\u0000\u0001\u0001\u0001\u0000\u0001\u0000\u0001\u001a", new Object[]{"strings_"});
            case 3:
                return new f();
            case 4:
                return new e(DEFAULT_INSTANCE);
            case 5:
                return DEFAULT_INSTANCE;
            case 6:
                O o = PARSER;
                if (o != null) {
                    return o;
                }
                synchronized (f.class) {
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

    public final InterfaceC1114v n() {
        return this.strings_;
    }
}

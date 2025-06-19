package androidx.datastore.preferences.protobuf;

import java.util.Collections;
import java.util.Iterator;
import java.util.Map;

/* renamed from: androidx.datastore.preferences.protobuf.p, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1109p {
    public static final /* synthetic */ int c = 0;
    public final W a = W.g();
    public boolean b;

    static {
        new C1109p(0);
    }

    public C1109p() {
    }

    public static void b(C1104k c1104k, o0 o0Var, int i, Object obj) {
        if (o0Var == o0.d) {
            c1104k.C(i, 3);
            ((AbstractC1094a) obj).b(c1104k);
            c1104k.C(i, 4);
        }
        c1104k.C(i, o0Var.b);
        switch (o0Var.ordinal()) {
            case 0:
                c1104k.w(Double.doubleToRawLongBits(((Double) obj).doubleValue()));
                break;
            case 1:
                c1104k.u(Float.floatToRawIntBits(((Float) obj).floatValue()));
                break;
            case 2:
                c1104k.G(((Long) obj).longValue());
                break;
            case 3:
                c1104k.G(((Long) obj).longValue());
                break;
            case 4:
                c1104k.y(((Integer) obj).intValue());
                break;
            case 5:
                c1104k.w(((Long) obj).longValue());
                break;
            case 6:
                c1104k.u(((Integer) obj).intValue());
                break;
            case 7:
                c1104k.o(((Boolean) obj).booleanValue() ? (byte) 1 : (byte) 0);
                break;
            case 8:
                if (!(obj instanceof C1100g)) {
                    c1104k.B((String) obj);
                    break;
                } else {
                    c1104k.s((C1100g) obj);
                    break;
                }
            case 9:
                ((AbstractC1094a) obj).b(c1104k);
                break;
            case 10:
                AbstractC1094a abstractC1094a = (AbstractC1094a) obj;
                c1104k.getClass();
                c1104k.E(((AbstractC1113u) abstractC1094a).a(null));
                abstractC1094a.b(c1104k);
                break;
            case 11:
                if (!(obj instanceof C1100g)) {
                    byte[] bArr = (byte[]) obj;
                    int length = bArr.length;
                    c1104k.E(length);
                    c1104k.p(bArr, 0, length);
                    break;
                } else {
                    c1104k.s((C1100g) obj);
                    break;
                }
            case 12:
                c1104k.E(((Integer) obj).intValue());
                break;
            case 13:
                c1104k.y(((Integer) obj).intValue());
                break;
            case 14:
                c1104k.u(((Integer) obj).intValue());
                break;
            case 15:
                c1104k.w(((Long) obj).longValue());
                break;
            case 16:
                int iIntValue = ((Integer) obj).intValue();
                c1104k.E((iIntValue >> 31) ^ (iIntValue << 1));
                break;
            case 17:
                long jLongValue = ((Long) obj).longValue();
                c1104k.G((jLongValue >> 63) ^ (jLongValue << 1));
                break;
        }
    }

    public final void a() {
        if (this.b) {
            return;
        }
        W w = this.a;
        int size = w.a.size();
        for (int i = 0; i < size; i++) {
            Map.Entry entryD = w.d(i);
            if (entryD.getValue() instanceof AbstractC1113u) {
                AbstractC1113u abstractC1113u = (AbstractC1113u) entryD.getValue();
                abstractC1113u.getClass();
                Q q = Q.c;
                q.getClass();
                q.a(abstractC1113u.getClass()).b(abstractC1113u);
                abstractC1113u.h();
            }
        }
        if (!w.c) {
            if (w.a.size() > 0) {
                w.d(0).getKey().getClass();
                throw new ClassCastException();
            }
            Iterator it2 = w.e().iterator();
            if (it2.hasNext()) {
                ((Map.Entry) it2.next()).getKey().getClass();
                throw new ClassCastException();
            }
        }
        if (!w.c) {
            w.b = w.b.isEmpty() ? Collections.EMPTY_MAP : Collections.unmodifiableMap(w.b);
            w.e = w.e.isEmpty() ? Collections.EMPTY_MAP : Collections.unmodifiableMap(w.e);
            w.c = true;
        }
        this.b = true;
    }

    public final Object clone() {
        C1109p c1109p = new C1109p();
        W w = this.a;
        if (w.a.size() > 0) {
            Map.Entry entryD = w.d(0);
            if (entryD.getKey() != null) {
                throw new ClassCastException();
            }
            entryD.getValue();
            throw null;
        }
        Iterator it2 = w.e().iterator();
        if (!it2.hasNext()) {
            return c1109p;
        }
        Map.Entry entry = (Map.Entry) it2.next();
        if (entry.getKey() != null) {
            throw new ClassCastException();
        }
        entry.getValue();
        throw null;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof C1109p) {
            return this.a.equals(((C1109p) obj).a);
        }
        return false;
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public C1109p(int i) {
        a();
        a();
    }
}

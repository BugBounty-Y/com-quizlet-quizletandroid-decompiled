package com.google.protobuf;

import java.util.Collections;
import java.util.Iterator;
import java.util.Map;

/* renamed from: com.google.protobuf.q, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4023q {
    public static final /* synthetic */ int c = 0;
    public final e0 a = new e0(16);
    public boolean b;

    static {
        new C4023q(0);
    }

    public C4023q() {
    }

    public static void b(AbstractC4018l abstractC4018l, B0 b0, int i, Object obj) {
        if (b0 == B0.e) {
            abstractC4018l.C(i, 3);
            ((AbstractC4004a) obj).i(abstractC4018l);
            abstractC4018l.C(i, 4);
        }
        abstractC4018l.C(i, b0.b);
        switch (b0.ordinal()) {
            case 0:
                abstractC4018l.v(Double.doubleToRawLongBits(((Double) obj).doubleValue()));
                break;
            case 1:
                abstractC4018l.t(Float.floatToRawIntBits(((Float) obj).floatValue()));
                break;
            case 2:
                abstractC4018l.G(((Long) obj).longValue());
                break;
            case 3:
                abstractC4018l.G(((Long) obj).longValue());
                break;
            case 4:
                abstractC4018l.x(((Integer) obj).intValue());
                break;
            case 5:
                abstractC4018l.v(((Long) obj).longValue());
                break;
            case 6:
                abstractC4018l.t(((Integer) obj).intValue());
                break;
            case 7:
                abstractC4018l.n(((Boolean) obj).booleanValue() ? (byte) 1 : (byte) 0);
                break;
            case 8:
                if (!(obj instanceof C4012f)) {
                    abstractC4018l.B((String) obj);
                    break;
                } else {
                    abstractC4018l.r((C4012f) obj);
                    break;
                }
            case 9:
                ((AbstractC4004a) obj).i(abstractC4018l);
                break;
            case 10:
                abstractC4018l.z((AbstractC4004a) obj);
                break;
            case 11:
                if (!(obj instanceof C4012f)) {
                    byte[] bArr = (byte[]) obj;
                    abstractC4018l.p(bArr.length, bArr);
                    break;
                } else {
                    abstractC4018l.r((C4012f) obj);
                    break;
                }
            case 12:
                abstractC4018l.E(((Integer) obj).intValue());
                break;
            case 13:
                if (!(obj instanceof InterfaceC4029x)) {
                    abstractC4018l.x(((Integer) obj).intValue());
                    break;
                } else {
                    abstractC4018l.x(((InterfaceC4029x) obj).a());
                    break;
                }
            case 14:
                abstractC4018l.t(((Integer) obj).intValue());
                break;
            case 15:
                abstractC4018l.v(((Long) obj).longValue());
                break;
            case 16:
                int iIntValue = ((Integer) obj).intValue();
                abstractC4018l.E((iIntValue >> 31) ^ (iIntValue << 1));
                break;
            case 17:
                long jLongValue = ((Long) obj).longValue();
                abstractC4018l.G((jLongValue >> 63) ^ (jLongValue << 1));
                break;
        }
    }

    public final void a() {
        e0 e0Var;
        if (this.b) {
            return;
        }
        int i = 0;
        while (true) {
            e0Var = this.a;
            if (i >= e0Var.b.size()) {
                break;
            }
            Map.Entry entryD = e0Var.d(i);
            if (entryD.getValue() instanceof AbstractC4027v) {
                AbstractC4027v abstractC4027v = (AbstractC4027v) entryD.getValue();
                abstractC4027v.getClass();
                Z z = Z.c;
                z.getClass();
                z.a(abstractC4027v.getClass()).b(abstractC4027v);
                abstractC4027v.q();
            }
            i++;
        }
        if (!e0Var.d) {
            if (e0Var.b.size() > 0) {
                e0Var.d(0).getKey().getClass();
                throw new ClassCastException();
            }
            Iterator it2 = e0Var.e().iterator();
            if (it2.hasNext()) {
                ((Map.Entry) it2.next()).getKey().getClass();
                throw new ClassCastException();
            }
        }
        if (!e0Var.d) {
            e0Var.c = e0Var.c.isEmpty() ? Collections.EMPTY_MAP : Collections.unmodifiableMap(e0Var.c);
            e0Var.f = e0Var.f.isEmpty() ? Collections.EMPTY_MAP : Collections.unmodifiableMap(e0Var.f);
            e0Var.d = true;
        }
        this.b = true;
    }

    public final Object clone() {
        C4023q c4023q = new C4023q();
        e0 e0Var = this.a;
        if (e0Var.b.size() > 0) {
            Map.Entry entryD = e0Var.d(0);
            if (entryD.getKey() != null) {
                throw new ClassCastException();
            }
            entryD.getValue();
            throw null;
        }
        Iterator it2 = e0Var.e().iterator();
        if (!it2.hasNext()) {
            return c4023q;
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
        if (obj instanceof C4023q) {
            return this.a.equals(((C4023q) obj).a);
        }
        return false;
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public C4023q(int i) {
        a();
        a();
    }
}

package androidx.compose.material3;

import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.material3.tokens.AbstractC0729c;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.graphics.C0861v;
import com.appsflyer.attribution.RequestError;
import com.comscore.streaming.EventType;

/* renamed from: androidx.compose.material3.b0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractC0590b0 {
    public static final androidx.compose.runtime.X0 a = new androidx.compose.runtime.X0(C0584a0.b);
    public static final androidx.compose.runtime.X0 b = new androidx.compose.runtime.X0(C0584a0.c);

    public static final long a(Z z, long j) {
        if (C0861v.c(j, z.a)) {
            return z.b;
        }
        if (C0861v.c(j, z.f)) {
            return z.g;
        }
        if (C0861v.c(j, z.j)) {
            return z.k;
        }
        if (C0861v.c(j, z.n)) {
            return z.o;
        }
        if (C0861v.c(j, z.w)) {
            return z.x;
        }
        if (C0861v.c(j, z.c)) {
            return z.d;
        }
        if (C0861v.c(j, z.h)) {
            return z.i;
        }
        if (C0861v.c(j, z.l)) {
            return z.m;
        }
        if (C0861v.c(j, z.y)) {
            return z.z;
        }
        if (C0861v.c(j, z.u)) {
            return z.v;
        }
        boolean zC = C0861v.c(j, z.p);
        long j2 = z.q;
        if (zC) {
            return j2;
        }
        if (C0861v.c(j, z.r)) {
            return z.s;
        }
        if (C0861v.c(j, z.D) || C0861v.c(j, z.F) || C0861v.c(j, z.G) || C0861v.c(j, z.H) || C0861v.c(j, z.I) || C0861v.c(j, z.J)) {
            return j2;
        }
        int i = C0861v.h;
        return C0861v.g;
    }

    public static final long b(long j, InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(-1680936624);
        long jA = a((Z) c0814p.j(a), j);
        if (jA == 16) {
            jA = ((C0861v) c0814p.j(AbstractC0669k0.a)).a;
        }
        c0814p.p(false);
        return jA;
    }

    public static final long c(Z z, int i) {
        switch (AbstractC0147y.k(i)) {
            case 0:
                return z.n;
            case 1:
                return z.w;
            case 2:
                return z.y;
            case 3:
                return z.v;
            case 4:
                return z.e;
            case 5:
                return z.u;
            case 6:
                return z.o;
            case 7:
                return z.x;
            case 8:
                return z.z;
            case 9:
                return z.b;
            case 10:
                return z.d;
            case 11:
            case 12:
            case 15:
            case 16:
            case 21:
            case EventType.WINDOW_STATE /* 22 */:
            case 27:
            case 28:
            case 32:
            case 33:
            default:
                return C0861v.g;
            case 13:
                return z.g;
            case 14:
                return z.i;
            case 17:
                return z.q;
            case 18:
                return z.s;
            case 19:
                return z.k;
            case 20:
                return z.m;
            case EventType.AUDIO /* 23 */:
                return z.A;
            case EventType.VIDEO /* 24 */:
                return z.B;
            case EventType.SUBS /* 25 */:
                return z.a;
            case EventType.CDN /* 26 */:
                return z.c;
            case 29:
                return z.C;
            case 30:
                return z.f;
            case 31:
                return z.h;
            case 34:
                return z.p;
            case 35:
                return z.D;
            case 36:
                return z.F;
            case 37:
                return z.G;
            case 38:
                return z.H;
            case 39:
                return z.I;
            case RequestError.NETWORK_FAILURE /* 40 */:
                return z.J;
            case RequestError.NO_DEV_KEY /* 41 */:
                return z.E;
            case 42:
                return z.t;
            case 43:
                return z.r;
            case 44:
                return z.j;
            case 45:
                return z.l;
        }
    }

    public static final long d(InterfaceC0806l interfaceC0806l, int i) {
        return c((Z) ((C0814p) interfaceC0806l).j(a), i);
    }

    public static Z e(long j, long j2, long j3, long j4, long j5, int i) {
        long j6 = (i & 1) != 0 ? AbstractC0729c.t : j;
        return new Z(j6, AbstractC0729c.j, AbstractC0729c.u, AbstractC0729c.k, AbstractC0729c.e, AbstractC0729c.w, AbstractC0729c.l, AbstractC0729c.x, AbstractC0729c.m, AbstractC0729c.H, AbstractC0729c.p, AbstractC0729c.I, AbstractC0729c.q, (i & 8192) != 0 ? AbstractC0729c.a : j2, AbstractC0729c.g, AbstractC0729c.y, AbstractC0729c.n, (131072 & i) != 0 ? AbstractC0729c.G : j3, (262144 & i) != 0 ? AbstractC0729c.o : j4, j6, AbstractC0729c.f, AbstractC0729c.d, (i & 4194304) != 0 ? AbstractC0729c.b : j5, AbstractC0729c.h, AbstractC0729c.c, AbstractC0729c.i, AbstractC0729c.r, AbstractC0729c.s, AbstractC0729c.v, AbstractC0729c.z, AbstractC0729c.F, AbstractC0729c.A, AbstractC0729c.B, AbstractC0729c.C, AbstractC0729c.D, AbstractC0729c.E);
    }
}

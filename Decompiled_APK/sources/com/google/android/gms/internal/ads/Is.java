package com.google.android.gms.internal.ads;

import android.os.Handler;
import android.os.HandlerThread;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.comscore.streaming.EventType;
import java.security.GeneralSecurityException;
import java.util.Iterator;
import javax.crypto.Cipher;

/* loaded from: classes2.dex */
public final /* synthetic */ class Is implements Bt, At, InterfaceC2205iy, InterfaceC1987dy, InterfaceC1857ay, Jx, Hx {
    public final /* synthetic */ int a;

    public /* synthetic */ Is(int i) {
        this.a = i;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2205iy, com.google.android.gms.internal.ads.Jx
    public C2377my a(AbstractC2025es abstractC2025es) {
        switch (this.a) {
            case EventType.WINDOW_STATE /* 22 */:
                Yw yw = (Yw) abstractC2025es;
                Qz qzX = Rz.x();
                Sz szW = Tz.w();
                Zw zw = yw.c;
                szW.e();
                Tz.A((Tz) szW.b, zw.a);
                Tz tz = (Tz) szW.c();
                qzX.e();
                Rz.B((Rz) qzX.b, tz);
                return C2377my.a("type.googleapis.com/google.crypto.tink.KmsAeadKey", ((Rz) qzX.c()).b(), 5, AbstractC1856ax.b(yw.c.b), yw.e);
            default:
                C1900bx c1900bx = (C1900bx) abstractC2025es;
                Uz uzX = Vz.x();
                Xz xzB = AbstractC1986dx.b(c1900bx.c);
                uzX.e();
                Vz.B((Vz) uzX.b, xzB);
                return C2377my.a("type.googleapis.com/google.crypto.tink.KmsEnvelopeAeadKey", ((Vz) uzX.c()).b(), 5, AbstractC1986dx.c(c1900bx.c.a), c1900bx.e);
        }
    }

    @Override // com.google.android.gms.internal.ads.At
    public Iterator e(C2883yp c2883yp, CharSequence charSequence) {
        return new C2887yt(charSequence);
    }

    @Override // com.google.android.gms.internal.ads.Hx
    public AbstractC2025es f(C2377my c2377my) throws GeneralSecurityException {
        switch (this.a) {
            case EventType.AUDIO /* 23 */:
                if (!c2377my.a.equals("type.googleapis.com/google.crypto.tink.KmsAeadKey")) {
                    throw new IllegalArgumentException("Wrong type URL in call to LegacyKmsAeadProtoSerialization.parseKey");
                }
                try {
                    BA ba = c2377my.c;
                    IA ia = IA.a;
                    C2305lB c2305lB = C2305lB.c;
                    Rz rzY = Rz.y(ba, IA.b);
                    if (rzY.w() == 0) {
                        return Yw.S(new Zw(rzY.z().z(), AbstractC1856ax.a(c2377my.e)), c2377my.f);
                    }
                    throw new GeneralSecurityException("KmsAeadKey are only accepted with version 0, got ".concat(String.valueOf(rzY)));
                } catch (zzgzh e) {
                    throw new GeneralSecurityException("Parsing KmsAeadKey failed: ", e);
                }
            default:
                if (!c2377my.a.equals("type.googleapis.com/google.crypto.tink.KmsEnvelopeAeadKey")) {
                    throw new IllegalArgumentException("Wrong type URL in call to LegacyKmsEnvelopeAeadProtoSerialization.parseKey");
                }
                try {
                    BA ba2 = c2377my.c;
                    IA ia2 = IA.a;
                    C2305lB c2305lB2 = C2305lB.c;
                    Vz vzY = Vz.y(ba2, IA.b);
                    if (vzY.w() == 0) {
                        return C1900bx.S(AbstractC1986dx.a(vzY.z(), c2377my.e), c2377my.f);
                    }
                    throw new GeneralSecurityException("KmsEnvelopeAeadKeys are only accepted with version 0, got ".concat(String.valueOf(vzY)));
                } catch (zzgzh e2) {
                    throw new GeneralSecurityException("Parsing KmsEnvelopeAeadKey failed: ", e2);
                }
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1857ay
    public AbstractC2547qw g(C2420ny c2420ny) throws GeneralSecurityException {
        switch (this.a) {
            case 21:
                Gz gz = c2420ny.b;
                if (!gz.B().equals("type.googleapis.com/google.crypto.tink.KmsAeadKey")) {
                    throw new IllegalArgumentException("Wrong type URL in call to LegacyKmsAeadProtoSerialization.parseParameters: ".concat(String.valueOf(gz.B())));
                }
                try {
                    BA baA = gz.A();
                    IA ia = IA.a;
                    C2305lB c2305lB = C2305lB.c;
                    return new Zw(Tz.y(baA, IA.b).z(), AbstractC1856ax.a(gz.z()));
                } catch (zzgzh e) {
                    throw new GeneralSecurityException("Parsing KmsAeadKeyFormat failed: ", e);
                }
            default:
                Gz gz2 = c2420ny.b;
                if (!gz2.B().equals("type.googleapis.com/google.crypto.tink.KmsEnvelopeAeadKey")) {
                    throw new IllegalArgumentException("Wrong type URL in call to LegacyKmsEnvelopeAeadProtoSerialization.parseParameters: ".concat(String.valueOf(gz2.B())));
                }
                try {
                    BA baA2 = gz2.A();
                    IA ia2 = IA.a;
                    C2305lB c2305lB2 = C2305lB.c;
                    return AbstractC1986dx.a(Xz.z(baA2, IA.b), gz2.z());
                } catch (zzgzh e2) {
                    throw new GeneralSecurityException("Parsing KmsEnvelopeAeadKeyFormat failed: ", e2);
                }
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1987dy
    public C2420ny h(AbstractC2547qw abstractC2547qw) {
        switch (this.a) {
            case 20:
                Zw zw = (Zw) abstractC2547qw;
                Fz fzW = Gz.w();
                fzW.h("type.googleapis.com/google.crypto.tink.KmsAeadKey");
                Sz szW = Tz.w();
                String str = zw.a;
                szW.e();
                Tz.A((Tz) szW.b, str);
                fzW.i(((Tz) szW.c()).b());
                fzW.g(AbstractC1856ax.b(zw.b));
                return C2420ny.a((Gz) fzW.c());
            default:
                C1943cx c1943cx = (C1943cx) abstractC2547qw;
                Fz fzW2 = Gz.w();
                fzW2.h("type.googleapis.com/google.crypto.tink.KmsEnvelopeAeadKey");
                fzW2.i(AbstractC1986dx.b(c1943cx).b());
                fzW2.g(AbstractC1986dx.c(c1943cx.a));
                return C2420ny.a((Gz) fzW2.c());
        }
    }

    @Override // com.google.android.gms.internal.ads.Bt
    public Object zza() {
        switch (this.a) {
            case 0:
                return -1;
            case 1:
                return -1;
            case 2:
                HandlerThread handlerThread = new HandlerThread("OverlayDisplayService", 10);
                handlerThread.start();
                return new Handler(handlerThread.getLooper());
            default:
                throw new IllegalStateException();
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2205iy, com.google.android.gms.internal.ads.Jx
    public Object a(AbstractC2025es abstractC2025es) throws GeneralSecurityException {
        byte[] bArrB;
        switch (this.a) {
            case 5:
                return C2347mA.b((Aw) abstractC2025es);
            case 6:
                Nw nw = (Nw) abstractC2025es;
                return new C2805wx(((C2604sA) nw.d.b).b(), nw.e);
            case 7:
                return Bx.b((Qw) abstractC2025es);
            case 8:
                return C2304lA.b((Jw) abstractC2025es);
            case 9:
                Tw tw = (Tw) abstractC2025es;
                C2883yp c2883yp = AbstractC2718uw.a;
                if (C2590rx.f.get() != null) {
                    return new C2590rx(((C2604sA) tw.d.b).b(), tw.e.b());
                }
                return new C2805wx(3, ((C2604sA) tw.d.b).b(), tw.e.b());
            case 10:
                C2162hx c2162hx = (C2162hx) abstractC2025es;
                C2883yp c2883yp2 = AbstractC2718uw.a;
                if (((Cipher) C2590rx.f.get()) != null) {
                    return new C2805wx(1, ((C2604sA) c2162hx.d.b).b(), c2162hx.e.b());
                }
                return new C2805wx(4, ((C2604sA) c2162hx.d.b).b(), c2162hx.e.b());
            case 11:
                C2074fx c2074fx = (C2074fx) abstractC2025es;
                return new C2848xx(((C2604sA) c2074fx.d.b).b(), c2074fx.e, c2074fx.c.b);
            case 12:
                Nx nx = (Nx) abstractC2025es;
                C2377my c2377my = nx.c;
                int i = Lx.b[AbstractC0147y.k(c2377my.d)];
                Kx kxA = Fx.d.a(InterfaceC2289kw.class, c2377my.a);
                Yz yz = Yz.RAW;
                AbstractC2025es abstractC2025esA = Xx.b.a(C2377my.a(kxA.a, c2377my.c, kxA.c, yz, null));
                Wx wx = Wx.b;
                InterfaceC2289kw interfaceC2289kw = (InterfaceC2289kw) ((C2291ky) wx.a.get()).a(abstractC2025esA, kxA.b);
                Yz yz2 = c2377my.e;
                int iOrdinal = yz2.ordinal();
                C2377my c2377my2 = nx.c;
                if (iOrdinal == 1) {
                    bArrB = Yx.b(c2377my2.f.intValue()).b();
                } else if (iOrdinal == 2) {
                    bArrB = Yx.a(c2377my2.f.intValue()).b();
                } else if (iOrdinal == 3) {
                    bArrB = Yx.a.b();
                } else {
                    if (iOrdinal != 4) {
                        throw new GeneralSecurityException("unknown output prefix type ".concat(String.valueOf(yz2)));
                    }
                    bArrB = Yx.a(c2377my2.f.intValue()).b();
                }
                return new C2805wx(interfaceC2289kw, bArrB);
            case 13:
                return C2347mA.b((Aw) abstractC2025es);
            case 14:
                return C2304lA.b((Jw) abstractC2025es);
            case 15:
                Nw nw2 = (Nw) abstractC2025es;
                return new C2805wx(((C2604sA) nw2.d.b).b(), nw2.e);
            case 16:
                return Bx.b((Qw) abstractC2025es);
            case 17:
                Tw tw2 = (Tw) abstractC2025es;
                C2163hy c2163hy = Uw.a;
                if (C2590rx.f.get() != null) {
                    return new C2590rx(((C2604sA) tw2.d.b).b(), tw2.e.b());
                }
                return new C2805wx(3, ((C2604sA) tw2.d.b).b(), tw2.e.b());
            case 18:
                C2163hy c2163hy2 = Ww.a;
                AbstractC2461ow.a(((Yw) abstractC2025es).c.a);
                throw null;
            case 19:
                Kx kx = Xw.a;
                AbstractC2461ow.a(((C1900bx) abstractC2025es).c.b);
                throw null;
            case 20:
            case 21:
            case EventType.WINDOW_STATE /* 22 */:
            case EventType.AUDIO /* 23 */:
            case EventType.VIDEO /* 24 */:
            case EventType.SUBS /* 25 */:
            case EventType.CDN /* 26 */:
            case 27:
            default:
                C2162hx c2162hx2 = (C2162hx) abstractC2025es;
                C2163hy c2163hy3 = AbstractC2204ix.a;
                if (((Cipher) C2590rx.f.get()) != null) {
                    return new C2805wx(1, ((C2604sA) c2162hx2.d.b).b(), c2162hx2.e.b());
                }
                return new C2805wx(4, ((C2604sA) c2162hx2.d.b).b(), c2162hx2.e.b());
            case 28:
                C2074fx c2074fx2 = (C2074fx) abstractC2025es;
                return new C2848xx(((C2604sA) c2074fx2.d.b).b(), c2074fx2.e, c2074fx2.c.b);
        }
    }
}

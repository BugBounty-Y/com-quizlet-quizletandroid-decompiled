package androidx.glance.appwidget.proto;

import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.core.view.AbstractC1047f0;
import androidx.glance.appwidget.protobuf.AbstractC1190b;
import androidx.glance.appwidget.protobuf.AbstractC1206s;
import androidx.glance.appwidget.protobuf.AbstractC1209v;
import androidx.glance.appwidget.protobuf.C1195g;
import androidx.glance.appwidget.protobuf.C1196h;
import androidx.glance.appwidget.protobuf.C1197i;
import androidx.glance.appwidget.protobuf.C1200l;
import androidx.glance.appwidget.protobuf.InterfaceC1208u;
import androidx.glance.appwidget.protobuf.InvalidProtocolBufferException;
import androidx.glance.appwidget.protobuf.K;
import androidx.glance.appwidget.protobuf.L;
import androidx.glance.appwidget.protobuf.M;
import androidx.glance.appwidget.protobuf.N;
import androidx.glance.appwidget.protobuf.O;
import androidx.glance.appwidget.protobuf.UninitializedMessageException;
import androidx.glance.appwidget.protobuf.r;
import java.io.IOException;
import java.io.InputStream;

/* loaded from: classes.dex */
public final class e extends AbstractC1206s {
    private static final e DEFAULT_INSTANCE;
    public static final int LAYOUT_FIELD_NUMBER = 1;
    public static final int NEXT_INDEX_FIELD_NUMBER = 2;
    private static volatile K PARSER;
    private InterfaceC1208u layout_ = M.d;
    private int nextIndex_;

    static {
        e eVar = new e();
        DEFAULT_INSTANCE = eVar;
        AbstractC1206s.i(e.class, eVar);
    }

    public static void k(e eVar, g gVar) {
        eVar.getClass();
        InterfaceC1208u interfaceC1208u = eVar.layout_;
        if (!((AbstractC1190b) interfaceC1208u).a) {
            M m = (M) interfaceC1208u;
            int i = m.c;
            eVar.layout_ = m.c(i == 0 ? 10 : i * 2);
        }
        ((M) eVar.layout_).add(gVar);
    }

    public static void l(e eVar) {
        eVar.getClass();
        eVar.layout_ = M.d;
    }

    public static void m(e eVar, int i) {
        eVar.nextIndex_ = i;
    }

    public static e n() {
        return DEFAULT_INSTANCE;
    }

    public static e q(InputStream inputStream) throws InvalidProtocolBufferException {
        AbstractC1047f0 c1196h;
        e eVar = DEFAULT_INSTANCE;
        if (inputStream == null) {
            byte[] bArr = AbstractC1209v.b;
            int length = bArr.length;
            c1196h = new C1195g(bArr, 0, length, false);
            try {
                c1196h.i(length);
            } catch (InvalidProtocolBufferException e) {
                throw new IllegalArgumentException(e);
            }
        } else {
            c1196h = new C1196h(inputStream);
        }
        C1200l c1200lA = C1200l.a();
        AbstractC1206s abstractC1206sH = eVar.h();
        try {
            L l = L.c;
            l.getClass();
            O oA = l.a(abstractC1206sH.getClass());
            C1197i c1197i = (C1197i) c1196h.b;
            if (c1197i == null) {
                c1197i = new C1197i(c1196h);
            }
            oA.f(abstractC1206sH, c1197i, c1200lA);
            oA.b(abstractC1206sH);
            if (AbstractC1206s.e(abstractC1206sH, true)) {
                return (e) abstractC1206sH;
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

    @Override // androidx.glance.appwidget.protobuf.AbstractC1206s
    public final Object b(int i) {
        K rVar;
        switch (AbstractC0147y.k(i)) {
            case 0:
                return (byte) 1;
            case 1:
                return null;
            case 2:
                return new N(DEFAULT_INSTANCE, "\u0000\u0002\u0000\u0000\u0001\u0002\u0002\u0000\u0001\u0000\u0001\u001b\u0002\u0004", new Object[]{"layout_", g.class, "nextIndex_"});
            case 3:
                return new e();
            case 4:
                return new d(DEFAULT_INSTANCE);
            case 5:
                return DEFAULT_INSTANCE;
            case 6:
                K k = PARSER;
                if (k != null) {
                    return k;
                }
                synchronized (e.class) {
                    try {
                        rVar = PARSER;
                        if (rVar == null) {
                            rVar = new r();
                            PARSER = rVar;
                        }
                    } catch (Throwable th) {
                        throw th;
                    }
                }
                return rVar;
            default:
                throw new UnsupportedOperationException();
        }
    }

    public final InterfaceC1208u o() {
        return this.layout_;
    }

    public final int p() {
        return this.nextIndex_;
    }
}

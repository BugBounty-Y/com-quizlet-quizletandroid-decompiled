package androidx.glance.appwidget.proto;

import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.glance.appwidget.protobuf.AbstractC1190b;
import androidx.glance.appwidget.protobuf.AbstractC1205q;
import androidx.glance.appwidget.protobuf.AbstractC1206s;
import androidx.glance.appwidget.protobuf.AbstractC1209v;
import androidx.glance.appwidget.protobuf.InterfaceC1208u;
import androidx.glance.appwidget.protobuf.K;
import androidx.glance.appwidget.protobuf.M;
import androidx.glance.appwidget.protobuf.N;
import androidx.glance.appwidget.protobuf.r;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.RandomAccess;

/* loaded from: classes.dex */
public final class i extends AbstractC1206s {
    public static final int CHILDREN_FIELD_NUMBER = 7;
    private static final i DEFAULT_INSTANCE;
    public static final int HASACTION_FIELD_NUMBER = 9;
    public static final int HAS_IMAGE_COLOR_FILTER_FIELD_NUMBER = 11;
    public static final int HAS_IMAGE_DESCRIPTION_FIELD_NUMBER = 10;
    public static final int HEIGHT_FIELD_NUMBER = 3;
    public static final int HORIZONTAL_ALIGNMENT_FIELD_NUMBER = 4;
    public static final int IDENTITY_FIELD_NUMBER = 8;
    public static final int IMAGE_SCALE_FIELD_NUMBER = 6;
    private static volatile K PARSER = null;
    public static final int TYPE_FIELD_NUMBER = 1;
    public static final int VERTICAL_ALIGNMENT_FIELD_NUMBER = 5;
    public static final int WIDTH_FIELD_NUMBER = 2;
    private InterfaceC1208u children_ = M.d;
    private boolean hasAction_;
    private boolean hasImageColorFilter_;
    private boolean hasImageDescription_;
    private int height_;
    private int horizontalAlignment_;
    private int identity_;
    private int imageScale_;
    private int type_;
    private int verticalAlignment_;
    private int width_;

    static {
        i iVar = new i();
        DEFAULT_INSTANCE = iVar;
        AbstractC1206s.i(i.class, iVar);
    }

    public static void k(i iVar, j jVar) {
        iVar.getClass();
        if (jVar == j.UNRECOGNIZED) {
            throw new IllegalArgumentException("Can't get the number of an unknown enum value.");
        }
        iVar.type_ = jVar.a;
    }

    public static void l(i iVar, b bVar) {
        iVar.getClass();
        iVar.width_ = bVar.a();
    }

    public static void m(i iVar, b bVar) {
        iVar.getClass();
        iVar.height_ = bVar.a();
    }

    public static void n(i iVar, c cVar) {
        iVar.getClass();
        if (cVar == c.UNRECOGNIZED) {
            throw new IllegalArgumentException("Can't get the number of an unknown enum value.");
        }
        iVar.horizontalAlignment_ = cVar.a;
    }

    public static void o(i iVar, k kVar) {
        iVar.getClass();
        if (kVar == k.UNRECOGNIZED) {
            throw new IllegalArgumentException("Can't get the number of an unknown enum value.");
        }
        iVar.verticalAlignment_ = kVar.a;
    }

    public static void p(i iVar, a aVar) {
        iVar.getClass();
        if (aVar == a.UNRECOGNIZED) {
            throw new IllegalArgumentException("Can't get the number of an unknown enum value.");
        }
        iVar.imageScale_ = aVar.a;
    }

    public static void q(i iVar) {
        iVar.getClass();
        iVar.identity_ = 1;
    }

    public static void r(i iVar, boolean z) {
        iVar.hasAction_ = z;
    }

    public static void s(i iVar, ArrayList arrayList) {
        InterfaceC1208u interfaceC1208u = iVar.children_;
        if (!((AbstractC1190b) interfaceC1208u).a) {
            M m = (M) interfaceC1208u;
            int i = m.c;
            iVar.children_ = m.c(i == 0 ? 10 : i * 2);
        }
        RandomAccess randomAccess = iVar.children_;
        Charset charset = AbstractC1209v.a;
        if (randomAccess instanceof ArrayList) {
            ((ArrayList) randomAccess).ensureCapacity(arrayList.size() + ((M) randomAccess).c);
        }
        M m2 = (M) randomAccess;
        int i2 = m2.c;
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            Object next = it2.next();
            if (next == null) {
                String str = "Element at index " + (m2.c - i2) + " is null.";
                for (int i3 = m2.c - 1; i3 >= i2; i3--) {
                    m2.remove(i3);
                }
                throw new NullPointerException(str);
            }
            m2.add(next);
        }
    }

    public static void t(i iVar, boolean z) {
        iVar.hasImageDescription_ = z;
    }

    public static void u(i iVar, boolean z) {
        iVar.hasImageColorFilter_ = z;
    }

    public static i v() {
        return DEFAULT_INSTANCE;
    }

    public static h w() {
        return (h) ((AbstractC1205q) DEFAULT_INSTANCE.b(5));
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
                return new N(DEFAULT_INSTANCE, "\u0000\u000b\u0000\u0000\u0001\u000b\u000b\u0000\u0001\u0000\u0001\f\u0002\f\u0003\f\u0004\f\u0005\f\u0006\f\u0007\u001b\b\f\t\u0007\n\u0007\u000b\u0007", new Object[]{"type_", "width_", "height_", "horizontalAlignment_", "verticalAlignment_", "imageScale_", "children_", i.class, "identity_", "hasAction_", "hasImageDescription_", "hasImageColorFilter_"});
            case 3:
                return new i();
            case 4:
                return new h(DEFAULT_INSTANCE);
            case 5:
                return DEFAULT_INSTANCE;
            case 6:
                K k = PARSER;
                if (k != null) {
                    return k;
                }
                synchronized (i.class) {
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
}

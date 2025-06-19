package com.google.android.gms.internal.ads;

import java.util.Collections;
import java.util.HashMap;

/* loaded from: classes2.dex */
public abstract class Ly {
    public static final C2272kf a;
    public static final C2272kf b;
    public static final C1944cy c;
    public static final Zx d;
    public static final Ix e;
    public static final Gx f;

    static {
        C2604sA c2604sAB = AbstractC2677ty.b("type.googleapis.com/google.crypto.tink.HmacKey");
        HashMap map = new HashMap();
        HashMap map2 = new HashMap();
        Yz yz = Yz.RAW;
        Dy dy = Dy.e;
        map.put(yz, dy);
        map2.put(dy, yz);
        Yz yz2 = Yz.TINK;
        Dy dy2 = Dy.b;
        map.put(yz2, dy2);
        map2.put(dy2, yz2);
        Yz yz3 = Yz.LEGACY;
        Dy dy3 = Dy.d;
        map.put(yz3, dy3);
        map2.put(dy3, yz3);
        Yz yz4 = Yz.CRUNCHY;
        Dy dy4 = Dy.c;
        map.put(yz4, dy4);
        map2.put(dy4, yz4);
        a = new C2272kf(Collections.unmodifiableMap(map), Collections.unmodifiableMap(map2));
        HashMap map3 = new HashMap();
        HashMap map4 = new HashMap();
        EnumC2764vz enumC2764vz = EnumC2764vz.SHA1;
        Cy cy = Cy.b;
        map3.put(enumC2764vz, cy);
        map4.put(cy, enumC2764vz);
        EnumC2764vz enumC2764vz2 = EnumC2764vz.SHA224;
        Cy cy2 = Cy.c;
        map3.put(enumC2764vz2, cy2);
        map4.put(cy2, enumC2764vz2);
        EnumC2764vz enumC2764vz3 = EnumC2764vz.SHA256;
        Cy cy3 = Cy.d;
        map3.put(enumC2764vz3, cy3);
        map4.put(cy3, enumC2764vz3);
        EnumC2764vz enumC2764vz4 = EnumC2764vz.SHA384;
        Cy cy4 = Cy.e;
        map3.put(enumC2764vz4, cy4);
        map4.put(cy4, enumC2764vz4);
        EnumC2764vz enumC2764vz5 = EnumC2764vz.SHA512;
        Cy cy5 = Cy.f;
        map3.put(enumC2764vz5, cy5);
        map4.put(cy5, enumC2764vz5);
        b = new C2272kf(Collections.unmodifiableMap(map3), Collections.unmodifiableMap(map4));
        c = new C1944cy(Ey.class, new C2806wy(9));
        d = new Zx(c2604sAB, new C2806wy(10));
        e = new Ix(Ay.class, new C2806wy(11));
        f = new Gx(c2604sAB, new C2806wy(12));
    }
}

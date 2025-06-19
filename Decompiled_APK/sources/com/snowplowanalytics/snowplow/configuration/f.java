package com.snowplowanalytics.snowplow.configuration;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class f {
    public static final f a;
    public static final f b;
    public static final f c;
    public static final f d;
    public static final f e;
    public static final f f;
    public static final f g;
    public static final f h;
    public static final f i;
    public static final f j;
    public static final f k;
    public static final f l;
    public static final f m;
    public static final f n;
    public static final f o;
    public static final f p;
    public static final /* synthetic */ f[] q;

    static {
        f fVar = new f("CARRIER", 0);
        a = fVar;
        f fVar2 = new f("NETWORK_TYPE", 1);
        b = fVar2;
        f fVar3 = new f("NETWORK_TECHNOLOGY", 2);
        c = fVar3;
        f fVar4 = new f("ANDROID_IDFA", 3);
        d = fVar4;
        f fVar5 = new f("PHYSICAL_MEMORY", 4);
        e = fVar5;
        f fVar6 = new f("SYSTEM_AVAILABLE_MEMORY", 5);
        f = fVar6;
        f fVar7 = new f("BATTERY_LEVEL", 6);
        g = fVar7;
        f fVar8 = new f("BATTERY_STATE", 7);
        h = fVar8;
        f fVar9 = new f("AVAILABLE_STORAGE", 8);
        i = fVar9;
        f fVar10 = new f("TOTAL_STORAGE", 9);
        j = fVar10;
        f fVar11 = new f("IS_PORTRAIT", 10);
        k = fVar11;
        f fVar12 = new f("RESOLUTION", 11);
        l = fVar12;
        f fVar13 = new f("SCALE", 12);
        m = fVar13;
        f fVar14 = new f("LANGUAGE", 13);
        n = fVar14;
        f fVar15 = new f("APP_SET_ID", 14);
        o = fVar15;
        f fVar16 = new f("APP_SET_ID_SCOPE", 15);
        p = fVar16;
        q = new f[]{fVar, fVar2, fVar3, fVar4, fVar5, fVar6, fVar7, fVar8, fVar9, fVar10, fVar11, fVar12, fVar13, fVar14, fVar15, fVar16};
    }

    public static f valueOf(String str) {
        return (f) Enum.valueOf(f.class, str);
    }

    public static f[] values() {
        return (f[]) q.clone();
    }
}

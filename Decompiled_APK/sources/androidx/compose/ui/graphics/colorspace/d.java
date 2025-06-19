package androidx.compose.ui.graphics.colorspace;

import androidx.camera.camera2.internal.s0;
import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes.dex */
public final class d {
    public static final float[] a;
    public static final float[] b;
    public static final q c;
    public static final q d;
    public static final q e;
    public static final q f;
    public static final q g;
    public static final q h;
    public static final q i;
    public static final q j;
    public static final q k;
    public static final q l;
    public static final q m;
    public static final q n;
    public static final q o;
    public static final q p;
    public static final k q;
    public static final k r;
    public static final q s;
    public static final l t;
    public static final c[] u;

    static {
        float[] fArr = {0.64f, 0.33f, 0.3f, 0.6f, 0.15f, 0.06f};
        a = fArr;
        float[] fArr2 = {0.67f, 0.33f, 0.21f, 0.71f, 0.14f, 0.08f};
        b = fArr2;
        r rVar = new r(2.4d, 0.9478672985781991d, 0.05213270142180095d, 0.07739938080495357d, 0.04045d);
        r rVar2 = new r(2.2d, 0.9478672985781991d, 0.05213270142180095d, 0.07739938080495357d, 0.04045d);
        s sVar = j.d;
        q qVar = new q("sRGB IEC61966-2.1", fArr, sVar, rVar, 0);
        c = qVar;
        q qVar2 = new q("sRGB IEC61966-2.1 (Linear)", fArr, sVar, 1.0d, DefinitionKt.NO_Float_VALUE, 1.0f, 1);
        d = qVar2;
        q qVar3 = new q("scRGB-nl IEC 61966-2-2:2003", fArr, sVar, null, new s0(5), new s0(6), -0.799f, 2.399f, rVar, 2);
        e = qVar3;
        q qVar4 = new q("scRGB IEC 61966-2-2:2003", fArr, sVar, 1.0d, -0.5f, 7.499f, 3);
        f = qVar4;
        q qVar5 = new q("Rec. ITU-R BT.709-5", new float[]{0.64f, 0.33f, 0.3f, 0.6f, 0.15f, 0.06f}, sVar, new r(2.2222222222222223d, 0.9099181073703367d, 0.09008189262966333d, 0.2222222222222222d, 0.081d), 4);
        g = qVar5;
        q qVar6 = new q("Rec. ITU-R BT.2020-1", new float[]{0.708f, 0.292f, 0.17f, 0.797f, 0.131f, 0.046f}, sVar, new r(2.2222222222222223d, 0.9096697898662786d, 0.09033021013372146d, 0.2222222222222222d, 0.08145d), 5);
        h = qVar6;
        q qVar7 = new q("SMPTE RP 431-2-2007 DCI (P3)", new float[]{0.68f, 0.32f, 0.265f, 0.69f, 0.15f, 0.06f}, new s(0.314f, 0.351f), 2.6d, DefinitionKt.NO_Float_VALUE, 1.0f, 6);
        i = qVar7;
        q qVar8 = new q("Display P3", new float[]{0.68f, 0.32f, 0.265f, 0.69f, 0.15f, 0.06f}, sVar, rVar, 7);
        j = qVar8;
        q qVar9 = new q("NTSC (1953)", fArr2, j.a, new r(2.2222222222222223d, 0.9099181073703367d, 0.09008189262966333d, 0.2222222222222222d, 0.081d), 8);
        k = qVar9;
        q qVar10 = new q("SMPTE-C RGB", new float[]{0.63f, 0.34f, 0.31f, 0.595f, 0.155f, 0.07f}, sVar, new r(2.2222222222222223d, 0.9099181073703367d, 0.09008189262966333d, 0.2222222222222222d, 0.081d), 9);
        l = qVar10;
        q qVar11 = new q("Adobe RGB (1998)", new float[]{0.64f, 0.33f, 0.21f, 0.71f, 0.15f, 0.06f}, sVar, 2.2d, DefinitionKt.NO_Float_VALUE, 1.0f, 10);
        m = qVar11;
        q qVar12 = new q("ROMM RGB ISO 22028-2:2013", new float[]{0.7347f, 0.2653f, 0.1596f, 0.8404f, 0.0366f, 1.0E-4f}, j.b, new r(1.8d, 1.0d, 0.0d, 0.0625d, 0.031248d), 11);
        n = qVar12;
        float[] fArr3 = {0.7347f, 0.2653f, DefinitionKt.NO_Float_VALUE, 1.0f, 1.0E-4f, -0.077f};
        s sVar2 = j.c;
        q qVar13 = new q("SMPTE ST 2065-1:2012 ACES", fArr3, sVar2, 1.0d, -65504.0f, 65504.0f, 12);
        o = qVar13;
        q qVar14 = new q("Academy S-2014-004 ACEScg", new float[]{0.713f, 0.293f, 0.165f, 0.83f, 0.128f, 0.044f}, sVar2, 1.0d, -65504.0f, 65504.0f, 13);
        p = qVar14;
        k kVar = new k(b.b, 14, 1, "Generic XYZ");
        q = kVar;
        long j2 = b.c;
        k kVar2 = new k(j2, 15, 0, "Generic L*a*b*");
        r = kVar2;
        q qVar15 = new q("None", fArr, sVar, rVar2, 16);
        s = qVar15;
        l lVar = new l(17, j2, "Oklab");
        t = lVar;
        u = new c[]{qVar, qVar2, qVar3, qVar4, qVar5, qVar6, qVar7, qVar8, qVar9, qVar10, qVar11, qVar12, qVar13, qVar14, kVar, kVar2, qVar15, lVar};
    }
}

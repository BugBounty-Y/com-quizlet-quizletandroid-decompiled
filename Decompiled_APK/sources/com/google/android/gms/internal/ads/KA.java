package com.google.android.gms.internal.ads;

/* JADX WARN: Enum visitor error
jadx.core.utils.exceptions.JadxRuntimeException: Init of enum field 'EF0' uses external variables
	at jadx.core.dex.visitors.EnumVisitor.createEnumFieldByConstructor(EnumVisitor.java:451)
	at jadx.core.dex.visitors.EnumVisitor.processEnumFieldByRegister(EnumVisitor.java:395)
	at jadx.core.dex.visitors.EnumVisitor.extractEnumFieldsFromFilledArray(EnumVisitor.java:324)
	at jadx.core.dex.visitors.EnumVisitor.extractEnumFieldsFromInsn(EnumVisitor.java:262)
	at jadx.core.dex.visitors.EnumVisitor.convertToEnum(EnumVisitor.java:151)
	at jadx.core.dex.visitors.EnumVisitor.visit(EnumVisitor.java:100)
 */
/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* loaded from: classes2.dex */
public final class KA {
    public static final KA b;
    public static final KA c;
    public static final KA[] d;
    public static final /* synthetic */ KA[] e;
    public final int a;

    /* JADX INFO: Fake field, exist only in values array */
    KA EF0;

    static {
        YA ya = YA.e;
        KA ka = new KA("DOUBLE", 0, 0, 1, ya);
        YA ya2 = YA.d;
        KA ka2 = new KA("FLOAT", 1, 1, 1, ya2);
        YA ya3 = YA.c;
        KA ka3 = new KA("INT64", 2, 2, 1, ya3);
        KA ka4 = new KA("UINT64", 3, 3, 1, ya3);
        YA ya4 = YA.b;
        KA ka5 = new KA("INT32", 4, 4, 1, ya4);
        KA ka6 = new KA("FIXED64", 5, 5, 1, ya3);
        KA ka7 = new KA("FIXED32", 6, 6, 1, ya4);
        YA ya5 = YA.f;
        KA ka8 = new KA("BOOL", 7, 7, 1, ya5);
        YA ya6 = YA.g;
        KA ka9 = new KA("STRING", 8, 8, 1, ya6);
        YA ya7 = YA.j;
        KA ka10 = new KA("MESSAGE", 9, 9, 1, ya7);
        YA ya8 = YA.h;
        KA ka11 = new KA("BYTES", 10, 10, 1, ya8);
        KA ka12 = new KA("UINT32", 11, 11, 1, ya4);
        YA ya9 = YA.i;
        KA ka13 = new KA("ENUM", 12, 12, 1, ya9);
        KA ka14 = new KA("SFIXED32", 13, 13, 1, ya4);
        KA ka15 = new KA("SFIXED64", 14, 14, 1, ya3);
        KA ka16 = new KA("SINT32", 15, 15, 1, ya4);
        KA ka17 = new KA("SINT64", 16, 16, 1, ya3);
        KA ka18 = new KA("GROUP", 17, 17, 1, ya7);
        KA ka19 = new KA("DOUBLE_LIST", 18, 18, 2, ya);
        KA ka20 = new KA("FLOAT_LIST", 19, 19, 2, ya2);
        KA ka21 = new KA("INT64_LIST", 20, 20, 2, ya3);
        KA ka22 = new KA("UINT64_LIST", 21, 21, 2, ya3);
        KA ka23 = new KA("INT32_LIST", 22, 22, 2, ya4);
        KA ka24 = new KA("FIXED64_LIST", 23, 23, 2, ya3);
        KA ka25 = new KA("FIXED32_LIST", 24, 24, 2, ya4);
        KA ka26 = new KA("BOOL_LIST", 25, 25, 2, ya5);
        KA ka27 = new KA("STRING_LIST", 26, 26, 2, ya6);
        KA ka28 = new KA("MESSAGE_LIST", 27, 27, 2, ya7);
        KA ka29 = new KA("BYTES_LIST", 28, 28, 2, ya8);
        KA ka30 = new KA("UINT32_LIST", 29, 29, 2, ya4);
        KA ka31 = new KA("ENUM_LIST", 30, 30, 2, ya9);
        KA ka32 = new KA("SFIXED32_LIST", 31, 31, 2, ya4);
        KA ka33 = new KA("SFIXED64_LIST", 32, 32, 2, ya3);
        KA ka34 = new KA("SINT32_LIST", 33, 33, 2, ya4);
        KA ka35 = new KA("SINT64_LIST", 34, 34, 2, ya3);
        KA ka36 = new KA("DOUBLE_LIST_PACKED", 35, 35, 3, ya);
        b = ka36;
        KA ka37 = new KA("FLOAT_LIST_PACKED", 36, 36, 3, ya2);
        KA ka38 = new KA("INT64_LIST_PACKED", 37, 37, 3, ya3);
        KA ka39 = new KA("UINT64_LIST_PACKED", 38, 38, 3, ya3);
        KA ka40 = new KA("INT32_LIST_PACKED", 39, 39, 3, ya4);
        KA ka41 = new KA("FIXED64_LIST_PACKED", 40, 40, 3, ya3);
        KA ka42 = new KA("FIXED32_LIST_PACKED", 41, 41, 3, ya4);
        KA ka43 = new KA("BOOL_LIST_PACKED", 42, 42, 3, ya5);
        KA ka44 = new KA("UINT32_LIST_PACKED", 43, 43, 3, ya4);
        KA ka45 = new KA("ENUM_LIST_PACKED", 44, 44, 3, ya9);
        KA ka46 = new KA("SFIXED32_LIST_PACKED", 45, 45, 3, ya4);
        KA ka47 = new KA("SFIXED64_LIST_PACKED", 46, 46, 3, ya3);
        KA ka48 = new KA("SINT32_LIST_PACKED", 47, 47, 3, ya4);
        KA ka49 = new KA("SINT64_LIST_PACKED", 48, 48, 3, ya3);
        c = ka49;
        e = new KA[]{ka, ka2, ka3, ka4, ka5, ka6, ka7, ka8, ka9, ka10, ka11, ka12, ka13, ka14, ka15, ka16, ka17, ka18, ka19, ka20, ka21, ka22, ka23, ka24, ka25, ka26, ka27, ka28, ka29, ka30, ka31, ka32, ka33, ka34, ka35, ka36, ka37, ka38, ka39, ka40, ka41, ka42, ka43, ka44, ka45, ka46, ka47, ka48, ka49, new KA("GROUP_LIST", 49, 49, 2, ya7), new KA("MAP", 50, 50, 4, YA.a)};
        KA[] kaArrValues = values();
        d = new KA[kaArrValues.length];
        for (KA ka50 : kaArrValues) {
            d[ka50.a] = ka50;
        }
    }

    public KA(String str, int i, int i2, int i3, YA ya) {
        this.a = i2;
        int i4 = i3 - 1;
        if (i4 == 1 || i4 == 3) {
            ya.getClass();
        }
        if (i3 == 1) {
            YA ya2 = YA.a;
            ya.ordinal();
        }
    }

    public static KA[] values() {
        return (KA[]) e.clone();
    }
}

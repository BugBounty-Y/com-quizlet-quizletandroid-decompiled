package com.google.android.gms.internal.measurement;

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
public final class S1 {
    public static final S1 b;
    public static final S1 c;
    public static final S1[] d;
    public static final /* synthetic */ S1[] e;
    public final int a;

    /* JADX INFO: Fake field, exist only in values array */
    S1 EF0;

    static {
        EnumC2985e2 enumC2985e2 = EnumC2985e2.e;
        S1 s1 = new S1("DOUBLE", 0, 0, 1, enumC2985e2);
        EnumC2985e2 enumC2985e22 = EnumC2985e2.d;
        S1 s12 = new S1("FLOAT", 1, 1, 1, enumC2985e22);
        EnumC2985e2 enumC2985e23 = EnumC2985e2.c;
        S1 s13 = new S1("INT64", 2, 2, 1, enumC2985e23);
        S1 s14 = new S1("UINT64", 3, 3, 1, enumC2985e23);
        EnumC2985e2 enumC2985e24 = EnumC2985e2.b;
        S1 s15 = new S1("INT32", 4, 4, 1, enumC2985e24);
        S1 s16 = new S1("FIXED64", 5, 5, 1, enumC2985e23);
        S1 s17 = new S1("FIXED32", 6, 6, 1, enumC2985e24);
        EnumC2985e2 enumC2985e25 = EnumC2985e2.f;
        S1 s18 = new S1("BOOL", 7, 7, 1, enumC2985e25);
        EnumC2985e2 enumC2985e26 = EnumC2985e2.g;
        S1 s19 = new S1("STRING", 8, 8, 1, enumC2985e26);
        EnumC2985e2 enumC2985e27 = EnumC2985e2.j;
        S1 s110 = new S1("MESSAGE", 9, 9, 1, enumC2985e27);
        EnumC2985e2 enumC2985e28 = EnumC2985e2.h;
        S1 s111 = new S1("BYTES", 10, 10, 1, enumC2985e28);
        S1 s112 = new S1("UINT32", 11, 11, 1, enumC2985e24);
        EnumC2985e2 enumC2985e29 = EnumC2985e2.i;
        S1 s113 = new S1("ENUM", 12, 12, 1, enumC2985e29);
        S1 s114 = new S1("SFIXED32", 13, 13, 1, enumC2985e24);
        S1 s115 = new S1("SFIXED64", 14, 14, 1, enumC2985e23);
        S1 s116 = new S1("SINT32", 15, 15, 1, enumC2985e24);
        S1 s117 = new S1("SINT64", 16, 16, 1, enumC2985e23);
        S1 s118 = new S1("GROUP", 17, 17, 1, enumC2985e27);
        S1 s119 = new S1("DOUBLE_LIST", 18, 18, 2, enumC2985e2);
        S1 s120 = new S1("FLOAT_LIST", 19, 19, 2, enumC2985e22);
        S1 s121 = new S1("INT64_LIST", 20, 20, 2, enumC2985e23);
        S1 s122 = new S1("UINT64_LIST", 21, 21, 2, enumC2985e23);
        S1 s123 = new S1("INT32_LIST", 22, 22, 2, enumC2985e24);
        S1 s124 = new S1("FIXED64_LIST", 23, 23, 2, enumC2985e23);
        S1 s125 = new S1("FIXED32_LIST", 24, 24, 2, enumC2985e24);
        S1 s126 = new S1("BOOL_LIST", 25, 25, 2, enumC2985e25);
        S1 s127 = new S1("STRING_LIST", 26, 26, 2, enumC2985e26);
        S1 s128 = new S1("MESSAGE_LIST", 27, 27, 2, enumC2985e27);
        S1 s129 = new S1("BYTES_LIST", 28, 28, 2, enumC2985e28);
        S1 s130 = new S1("UINT32_LIST", 29, 29, 2, enumC2985e24);
        S1 s131 = new S1("ENUM_LIST", 30, 30, 2, enumC2985e29);
        S1 s132 = new S1("SFIXED32_LIST", 31, 31, 2, enumC2985e24);
        S1 s133 = new S1("SFIXED64_LIST", 32, 32, 2, enumC2985e23);
        S1 s134 = new S1("SINT32_LIST", 33, 33, 2, enumC2985e24);
        S1 s135 = new S1("SINT64_LIST", 34, 34, 2, enumC2985e23);
        S1 s136 = new S1("DOUBLE_LIST_PACKED", 35, 35, 3, enumC2985e2);
        b = s136;
        S1 s137 = new S1("FLOAT_LIST_PACKED", 36, 36, 3, enumC2985e22);
        S1 s138 = new S1("INT64_LIST_PACKED", 37, 37, 3, enumC2985e23);
        S1 s139 = new S1("UINT64_LIST_PACKED", 38, 38, 3, enumC2985e23);
        S1 s140 = new S1("INT32_LIST_PACKED", 39, 39, 3, enumC2985e24);
        S1 s141 = new S1("FIXED64_LIST_PACKED", 40, 40, 3, enumC2985e23);
        S1 s142 = new S1("FIXED32_LIST_PACKED", 41, 41, 3, enumC2985e24);
        S1 s143 = new S1("BOOL_LIST_PACKED", 42, 42, 3, enumC2985e25);
        S1 s144 = new S1("UINT32_LIST_PACKED", 43, 43, 3, enumC2985e24);
        S1 s145 = new S1("ENUM_LIST_PACKED", 44, 44, 3, enumC2985e29);
        S1 s146 = new S1("SFIXED32_LIST_PACKED", 45, 45, 3, enumC2985e24);
        S1 s147 = new S1("SFIXED64_LIST_PACKED", 46, 46, 3, enumC2985e23);
        S1 s148 = new S1("SINT32_LIST_PACKED", 47, 47, 3, enumC2985e24);
        S1 s149 = new S1("SINT64_LIST_PACKED", 48, 48, 3, enumC2985e23);
        c = s149;
        e = new S1[]{s1, s12, s13, s14, s15, s16, s17, s18, s19, s110, s111, s112, s113, s114, s115, s116, s117, s118, s119, s120, s121, s122, s123, s124, s125, s126, s127, s128, s129, s130, s131, s132, s133, s134, s135, s136, s137, s138, s139, s140, s141, s142, s143, s144, s145, s146, s147, s148, s149, new S1("GROUP_LIST", 49, 49, 2, enumC2985e27), new S1("MAP", 50, 50, 4, EnumC2985e2.a)};
        S1[] s1ArrValues = values();
        d = new S1[s1ArrValues.length];
        for (S1 s150 : s1ArrValues) {
            d[s150.a] = s150;
        }
    }

    public S1(String str, int i, int i2, int i3, EnumC2985e2 enumC2985e2) {
        this.a = i2;
        int i4 = i3 - 1;
        if (i4 == 1 || i4 == 3) {
            enumC2985e2.getClass();
        }
        if (i3 == 1) {
            EnumC2985e2 enumC2985e22 = EnumC2985e2.a;
            enumC2985e2.ordinal();
        }
    }

    public static S1[] values() {
        return (S1[]) e.clone();
    }
}

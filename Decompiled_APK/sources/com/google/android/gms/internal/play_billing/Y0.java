package com.google.android.gms.internal.play_billing;

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
public final class Y0 {
    public static final Y0 b;
    public static final Y0 c;
    public static final Y0[] d;
    public static final /* synthetic */ Y0[] e;
    public final int a;

    /* JADX INFO: Fake field, exist only in values array */
    Y0 EF0;

    static {
        EnumC3805i1 enumC3805i1 = EnumC3805i1.e;
        Y0 y0 = new Y0("DOUBLE", 0, 0, 1, enumC3805i1);
        EnumC3805i1 enumC3805i12 = EnumC3805i1.d;
        Y0 y02 = new Y0("FLOAT", 1, 1, 1, enumC3805i12);
        EnumC3805i1 enumC3805i13 = EnumC3805i1.c;
        Y0 y03 = new Y0("INT64", 2, 2, 1, enumC3805i13);
        Y0 y04 = new Y0("UINT64", 3, 3, 1, enumC3805i13);
        EnumC3805i1 enumC3805i14 = EnumC3805i1.b;
        Y0 y05 = new Y0("INT32", 4, 4, 1, enumC3805i14);
        Y0 y06 = new Y0("FIXED64", 5, 5, 1, enumC3805i13);
        Y0 y07 = new Y0("FIXED32", 6, 6, 1, enumC3805i14);
        EnumC3805i1 enumC3805i15 = EnumC3805i1.f;
        Y0 y08 = new Y0("BOOL", 7, 7, 1, enumC3805i15);
        EnumC3805i1 enumC3805i16 = EnumC3805i1.g;
        Y0 y09 = new Y0("STRING", 8, 8, 1, enumC3805i16);
        EnumC3805i1 enumC3805i17 = EnumC3805i1.j;
        Y0 y010 = new Y0("MESSAGE", 9, 9, 1, enumC3805i17);
        EnumC3805i1 enumC3805i18 = EnumC3805i1.h;
        Y0 y011 = new Y0("BYTES", 10, 10, 1, enumC3805i18);
        Y0 y012 = new Y0("UINT32", 11, 11, 1, enumC3805i14);
        EnumC3805i1 enumC3805i19 = EnumC3805i1.i;
        Y0 y013 = new Y0("ENUM", 12, 12, 1, enumC3805i19);
        Y0 y014 = new Y0("SFIXED32", 13, 13, 1, enumC3805i14);
        Y0 y015 = new Y0("SFIXED64", 14, 14, 1, enumC3805i13);
        Y0 y016 = new Y0("SINT32", 15, 15, 1, enumC3805i14);
        Y0 y017 = new Y0("SINT64", 16, 16, 1, enumC3805i13);
        Y0 y018 = new Y0("GROUP", 17, 17, 1, enumC3805i17);
        Y0 y019 = new Y0("DOUBLE_LIST", 18, 18, 2, enumC3805i1);
        Y0 y020 = new Y0("FLOAT_LIST", 19, 19, 2, enumC3805i12);
        Y0 y021 = new Y0("INT64_LIST", 20, 20, 2, enumC3805i13);
        Y0 y022 = new Y0("UINT64_LIST", 21, 21, 2, enumC3805i13);
        Y0 y023 = new Y0("INT32_LIST", 22, 22, 2, enumC3805i14);
        Y0 y024 = new Y0("FIXED64_LIST", 23, 23, 2, enumC3805i13);
        Y0 y025 = new Y0("FIXED32_LIST", 24, 24, 2, enumC3805i14);
        Y0 y026 = new Y0("BOOL_LIST", 25, 25, 2, enumC3805i15);
        Y0 y027 = new Y0("STRING_LIST", 26, 26, 2, enumC3805i16);
        Y0 y028 = new Y0("MESSAGE_LIST", 27, 27, 2, enumC3805i17);
        Y0 y029 = new Y0("BYTES_LIST", 28, 28, 2, enumC3805i18);
        Y0 y030 = new Y0("UINT32_LIST", 29, 29, 2, enumC3805i14);
        Y0 y031 = new Y0("ENUM_LIST", 30, 30, 2, enumC3805i19);
        Y0 y032 = new Y0("SFIXED32_LIST", 31, 31, 2, enumC3805i14);
        Y0 y033 = new Y0("SFIXED64_LIST", 32, 32, 2, enumC3805i13);
        Y0 y034 = new Y0("SINT32_LIST", 33, 33, 2, enumC3805i14);
        Y0 y035 = new Y0("SINT64_LIST", 34, 34, 2, enumC3805i13);
        Y0 y036 = new Y0("DOUBLE_LIST_PACKED", 35, 35, 3, enumC3805i1);
        b = y036;
        Y0 y037 = new Y0("FLOAT_LIST_PACKED", 36, 36, 3, enumC3805i12);
        Y0 y038 = new Y0("INT64_LIST_PACKED", 37, 37, 3, enumC3805i13);
        Y0 y039 = new Y0("UINT64_LIST_PACKED", 38, 38, 3, enumC3805i13);
        Y0 y040 = new Y0("INT32_LIST_PACKED", 39, 39, 3, enumC3805i14);
        Y0 y041 = new Y0("FIXED64_LIST_PACKED", 40, 40, 3, enumC3805i13);
        Y0 y042 = new Y0("FIXED32_LIST_PACKED", 41, 41, 3, enumC3805i14);
        Y0 y043 = new Y0("BOOL_LIST_PACKED", 42, 42, 3, enumC3805i15);
        Y0 y044 = new Y0("UINT32_LIST_PACKED", 43, 43, 3, enumC3805i14);
        Y0 y045 = new Y0("ENUM_LIST_PACKED", 44, 44, 3, enumC3805i19);
        Y0 y046 = new Y0("SFIXED32_LIST_PACKED", 45, 45, 3, enumC3805i14);
        Y0 y047 = new Y0("SFIXED64_LIST_PACKED", 46, 46, 3, enumC3805i13);
        Y0 y048 = new Y0("SINT32_LIST_PACKED", 47, 47, 3, enumC3805i14);
        Y0 y049 = new Y0("SINT64_LIST_PACKED", 48, 48, 3, enumC3805i13);
        c = y049;
        e = new Y0[]{y0, y02, y03, y04, y05, y06, y07, y08, y09, y010, y011, y012, y013, y014, y015, y016, y017, y018, y019, y020, y021, y022, y023, y024, y025, y026, y027, y028, y029, y030, y031, y032, y033, y034, y035, y036, y037, y038, y039, y040, y041, y042, y043, y044, y045, y046, y047, y048, y049, new Y0("GROUP_LIST", 49, 49, 2, enumC3805i17), new Y0("MAP", 50, 50, 4, EnumC3805i1.a)};
        Y0[] y0ArrValues = values();
        d = new Y0[y0ArrValues.length];
        for (Y0 y050 : y0ArrValues) {
            d[y050.a] = y050;
        }
    }

    public Y0(String str, int i, int i2, int i3, EnumC3805i1 enumC3805i1) {
        this.a = i2;
        int i4 = i3 - 1;
        if (i4 == 1 || i4 == 3) {
            enumC3805i1.getClass();
        }
        if (i3 == 1) {
            EnumC3805i1 enumC3805i12 = EnumC3805i1.a;
            enumC3805i1.ordinal();
        }
    }

    public static Y0[] values() {
        return (Y0[]) e.clone();
    }
}

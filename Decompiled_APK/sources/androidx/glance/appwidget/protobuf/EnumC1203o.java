package androidx.glance.appwidget.protobuf;

import androidx.camera.camera2.internal.AbstractC0147y;

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
/* renamed from: androidx.glance.appwidget.protobuf.o, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class EnumC1203o {
    public static final EnumC1203o b;
    public static final EnumC1203o c;
    public static final EnumC1203o[] d;
    public static final /* synthetic */ EnumC1203o[] e;
    public final int a;

    /* JADX INFO: Fake field, exist only in values array */
    EnumC1203o EF0;

    static {
        EnumC1210w enumC1210w = EnumC1210w.DOUBLE;
        EnumC1203o enumC1203o = new EnumC1203o("DOUBLE", 0, 0, 1, enumC1210w);
        EnumC1210w enumC1210w2 = EnumC1210w.FLOAT;
        EnumC1203o enumC1203o2 = new EnumC1203o("FLOAT", 1, 1, 1, enumC1210w2);
        EnumC1210w enumC1210w3 = EnumC1210w.LONG;
        EnumC1203o enumC1203o3 = new EnumC1203o("INT64", 2, 2, 1, enumC1210w3);
        EnumC1203o enumC1203o4 = new EnumC1203o("UINT64", 3, 3, 1, enumC1210w3);
        EnumC1210w enumC1210w4 = EnumC1210w.INT;
        EnumC1203o enumC1203o5 = new EnumC1203o("INT32", 4, 4, 1, enumC1210w4);
        EnumC1203o enumC1203o6 = new EnumC1203o("FIXED64", 5, 5, 1, enumC1210w3);
        EnumC1203o enumC1203o7 = new EnumC1203o("FIXED32", 6, 6, 1, enumC1210w4);
        EnumC1210w enumC1210w5 = EnumC1210w.BOOLEAN;
        EnumC1203o enumC1203o8 = new EnumC1203o("BOOL", 7, 7, 1, enumC1210w5);
        EnumC1210w enumC1210w6 = EnumC1210w.STRING;
        EnumC1203o enumC1203o9 = new EnumC1203o("STRING", 8, 8, 1, enumC1210w6);
        EnumC1210w enumC1210w7 = EnumC1210w.MESSAGE;
        EnumC1203o enumC1203o10 = new EnumC1203o("MESSAGE", 9, 9, 1, enumC1210w7);
        EnumC1210w enumC1210w8 = EnumC1210w.BYTE_STRING;
        EnumC1203o enumC1203o11 = new EnumC1203o("BYTES", 10, 10, 1, enumC1210w8);
        EnumC1203o enumC1203o12 = new EnumC1203o("UINT32", 11, 11, 1, enumC1210w4);
        EnumC1210w enumC1210w9 = EnumC1210w.ENUM;
        EnumC1203o enumC1203o13 = new EnumC1203o("ENUM", 12, 12, 1, enumC1210w9);
        EnumC1203o enumC1203o14 = new EnumC1203o("SFIXED32", 13, 13, 1, enumC1210w4);
        EnumC1203o enumC1203o15 = new EnumC1203o("SFIXED64", 14, 14, 1, enumC1210w3);
        EnumC1203o enumC1203o16 = new EnumC1203o("SINT32", 15, 15, 1, enumC1210w4);
        EnumC1203o enumC1203o17 = new EnumC1203o("SINT64", 16, 16, 1, enumC1210w3);
        EnumC1203o enumC1203o18 = new EnumC1203o("GROUP", 17, 17, 1, enumC1210w7);
        EnumC1203o enumC1203o19 = new EnumC1203o("DOUBLE_LIST", 18, 18, 2, enumC1210w);
        EnumC1203o enumC1203o20 = new EnumC1203o("FLOAT_LIST", 19, 19, 2, enumC1210w2);
        EnumC1203o enumC1203o21 = new EnumC1203o("INT64_LIST", 20, 20, 2, enumC1210w3);
        EnumC1203o enumC1203o22 = new EnumC1203o("UINT64_LIST", 21, 21, 2, enumC1210w3);
        EnumC1203o enumC1203o23 = new EnumC1203o("INT32_LIST", 22, 22, 2, enumC1210w4);
        EnumC1203o enumC1203o24 = new EnumC1203o("FIXED64_LIST", 23, 23, 2, enumC1210w3);
        EnumC1203o enumC1203o25 = new EnumC1203o("FIXED32_LIST", 24, 24, 2, enumC1210w4);
        EnumC1203o enumC1203o26 = new EnumC1203o("BOOL_LIST", 25, 25, 2, enumC1210w5);
        EnumC1203o enumC1203o27 = new EnumC1203o("STRING_LIST", 26, 26, 2, enumC1210w6);
        EnumC1203o enumC1203o28 = new EnumC1203o("MESSAGE_LIST", 27, 27, 2, enumC1210w7);
        EnumC1203o enumC1203o29 = new EnumC1203o("BYTES_LIST", 28, 28, 2, enumC1210w8);
        EnumC1203o enumC1203o30 = new EnumC1203o("UINT32_LIST", 29, 29, 2, enumC1210w4);
        EnumC1203o enumC1203o31 = new EnumC1203o("ENUM_LIST", 30, 30, 2, enumC1210w9);
        EnumC1203o enumC1203o32 = new EnumC1203o("SFIXED32_LIST", 31, 31, 2, enumC1210w4);
        EnumC1203o enumC1203o33 = new EnumC1203o("SFIXED64_LIST", 32, 32, 2, enumC1210w3);
        EnumC1203o enumC1203o34 = new EnumC1203o("SINT32_LIST", 33, 33, 2, enumC1210w4);
        EnumC1203o enumC1203o35 = new EnumC1203o("SINT64_LIST", 34, 34, 2, enumC1210w3);
        EnumC1203o enumC1203o36 = new EnumC1203o("DOUBLE_LIST_PACKED", 35, 35, 3, enumC1210w);
        b = enumC1203o36;
        EnumC1203o enumC1203o37 = new EnumC1203o("FLOAT_LIST_PACKED", 36, 36, 3, enumC1210w2);
        EnumC1203o enumC1203o38 = new EnumC1203o("INT64_LIST_PACKED", 37, 37, 3, enumC1210w3);
        EnumC1203o enumC1203o39 = new EnumC1203o("UINT64_LIST_PACKED", 38, 38, 3, enumC1210w3);
        EnumC1203o enumC1203o40 = new EnumC1203o("INT32_LIST_PACKED", 39, 39, 3, enumC1210w4);
        EnumC1203o enumC1203o41 = new EnumC1203o("FIXED64_LIST_PACKED", 40, 40, 3, enumC1210w3);
        EnumC1203o enumC1203o42 = new EnumC1203o("FIXED32_LIST_PACKED", 41, 41, 3, enumC1210w4);
        EnumC1203o enumC1203o43 = new EnumC1203o("BOOL_LIST_PACKED", 42, 42, 3, enumC1210w5);
        EnumC1203o enumC1203o44 = new EnumC1203o("UINT32_LIST_PACKED", 43, 43, 3, enumC1210w4);
        EnumC1203o enumC1203o45 = new EnumC1203o("ENUM_LIST_PACKED", 44, 44, 3, enumC1210w9);
        EnumC1203o enumC1203o46 = new EnumC1203o("SFIXED32_LIST_PACKED", 45, 45, 3, enumC1210w4);
        EnumC1203o enumC1203o47 = new EnumC1203o("SFIXED64_LIST_PACKED", 46, 46, 3, enumC1210w3);
        EnumC1203o enumC1203o48 = new EnumC1203o("SINT32_LIST_PACKED", 47, 47, 3, enumC1210w4);
        EnumC1203o enumC1203o49 = new EnumC1203o("SINT64_LIST_PACKED", 48, 48, 3, enumC1210w3);
        c = enumC1203o49;
        e = new EnumC1203o[]{enumC1203o, enumC1203o2, enumC1203o3, enumC1203o4, enumC1203o5, enumC1203o6, enumC1203o7, enumC1203o8, enumC1203o9, enumC1203o10, enumC1203o11, enumC1203o12, enumC1203o13, enumC1203o14, enumC1203o15, enumC1203o16, enumC1203o17, enumC1203o18, enumC1203o19, enumC1203o20, enumC1203o21, enumC1203o22, enumC1203o23, enumC1203o24, enumC1203o25, enumC1203o26, enumC1203o27, enumC1203o28, enumC1203o29, enumC1203o30, enumC1203o31, enumC1203o32, enumC1203o33, enumC1203o34, enumC1203o35, enumC1203o36, enumC1203o37, enumC1203o38, enumC1203o39, enumC1203o40, enumC1203o41, enumC1203o42, enumC1203o43, enumC1203o44, enumC1203o45, enumC1203o46, enumC1203o47, enumC1203o48, enumC1203o49, new EnumC1203o("GROUP_LIST", 49, 49, 2, enumC1210w7), new EnumC1203o("MAP", 50, 50, 4, EnumC1210w.VOID)};
        EnumC1203o[] enumC1203oArrValues = values();
        d = new EnumC1203o[enumC1203oArrValues.length];
        for (EnumC1203o enumC1203o50 : enumC1203oArrValues) {
            d[enumC1203o50.a] = enumC1203o50;
        }
    }

    public EnumC1203o(String str, int i, int i2, int i3, EnumC1210w enumC1210w) {
        this.a = i2;
        int iK = AbstractC0147y.k(i3);
        if (iK == 1 || iK == 3) {
            enumC1210w.getClass();
        }
        if (i3 == 1) {
            enumC1210w.ordinal();
        }
    }

    public static EnumC1203o valueOf(String str) {
        return (EnumC1203o) Enum.valueOf(EnumC1203o.class, str);
    }

    public static EnumC1203o[] values() {
        return (EnumC1203o[]) e.clone();
    }
}

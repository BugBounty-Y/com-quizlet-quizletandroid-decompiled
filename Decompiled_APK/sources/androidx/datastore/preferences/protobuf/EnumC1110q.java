package androidx.datastore.preferences.protobuf;

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
/* renamed from: androidx.datastore.preferences.protobuf.q, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class EnumC1110q {
    public static final EnumC1110q b;
    public static final EnumC1110q c;
    public static final EnumC1110q[] d;
    public static final /* synthetic */ EnumC1110q[] e;
    public final int a;

    /* JADX INFO: Fake field, exist only in values array */
    EnumC1110q EF0;

    static {
        EnumC1116x enumC1116x = EnumC1116x.DOUBLE;
        EnumC1110q enumC1110q = new EnumC1110q("DOUBLE", 0, 0, 1, enumC1116x);
        EnumC1116x enumC1116x2 = EnumC1116x.FLOAT;
        EnumC1110q enumC1110q2 = new EnumC1110q("FLOAT", 1, 1, 1, enumC1116x2);
        EnumC1116x enumC1116x3 = EnumC1116x.LONG;
        EnumC1110q enumC1110q3 = new EnumC1110q("INT64", 2, 2, 1, enumC1116x3);
        EnumC1110q enumC1110q4 = new EnumC1110q("UINT64", 3, 3, 1, enumC1116x3);
        EnumC1116x enumC1116x4 = EnumC1116x.INT;
        EnumC1110q enumC1110q5 = new EnumC1110q("INT32", 4, 4, 1, enumC1116x4);
        EnumC1110q enumC1110q6 = new EnumC1110q("FIXED64", 5, 5, 1, enumC1116x3);
        EnumC1110q enumC1110q7 = new EnumC1110q("FIXED32", 6, 6, 1, enumC1116x4);
        EnumC1116x enumC1116x5 = EnumC1116x.BOOLEAN;
        EnumC1110q enumC1110q8 = new EnumC1110q("BOOL", 7, 7, 1, enumC1116x5);
        EnumC1116x enumC1116x6 = EnumC1116x.STRING;
        EnumC1110q enumC1110q9 = new EnumC1110q("STRING", 8, 8, 1, enumC1116x6);
        EnumC1116x enumC1116x7 = EnumC1116x.MESSAGE;
        EnumC1110q enumC1110q10 = new EnumC1110q("MESSAGE", 9, 9, 1, enumC1116x7);
        EnumC1116x enumC1116x8 = EnumC1116x.BYTE_STRING;
        EnumC1110q enumC1110q11 = new EnumC1110q("BYTES", 10, 10, 1, enumC1116x8);
        EnumC1110q enumC1110q12 = new EnumC1110q("UINT32", 11, 11, 1, enumC1116x4);
        EnumC1116x enumC1116x9 = EnumC1116x.ENUM;
        EnumC1110q enumC1110q13 = new EnumC1110q("ENUM", 12, 12, 1, enumC1116x9);
        EnumC1110q enumC1110q14 = new EnumC1110q("SFIXED32", 13, 13, 1, enumC1116x4);
        EnumC1110q enumC1110q15 = new EnumC1110q("SFIXED64", 14, 14, 1, enumC1116x3);
        EnumC1110q enumC1110q16 = new EnumC1110q("SINT32", 15, 15, 1, enumC1116x4);
        EnumC1110q enumC1110q17 = new EnumC1110q("SINT64", 16, 16, 1, enumC1116x3);
        EnumC1110q enumC1110q18 = new EnumC1110q("GROUP", 17, 17, 1, enumC1116x7);
        EnumC1110q enumC1110q19 = new EnumC1110q("DOUBLE_LIST", 18, 18, 2, enumC1116x);
        EnumC1110q enumC1110q20 = new EnumC1110q("FLOAT_LIST", 19, 19, 2, enumC1116x2);
        EnumC1110q enumC1110q21 = new EnumC1110q("INT64_LIST", 20, 20, 2, enumC1116x3);
        EnumC1110q enumC1110q22 = new EnumC1110q("UINT64_LIST", 21, 21, 2, enumC1116x3);
        EnumC1110q enumC1110q23 = new EnumC1110q("INT32_LIST", 22, 22, 2, enumC1116x4);
        EnumC1110q enumC1110q24 = new EnumC1110q("FIXED64_LIST", 23, 23, 2, enumC1116x3);
        EnumC1110q enumC1110q25 = new EnumC1110q("FIXED32_LIST", 24, 24, 2, enumC1116x4);
        EnumC1110q enumC1110q26 = new EnumC1110q("BOOL_LIST", 25, 25, 2, enumC1116x5);
        EnumC1110q enumC1110q27 = new EnumC1110q("STRING_LIST", 26, 26, 2, enumC1116x6);
        EnumC1110q enumC1110q28 = new EnumC1110q("MESSAGE_LIST", 27, 27, 2, enumC1116x7);
        EnumC1110q enumC1110q29 = new EnumC1110q("BYTES_LIST", 28, 28, 2, enumC1116x8);
        EnumC1110q enumC1110q30 = new EnumC1110q("UINT32_LIST", 29, 29, 2, enumC1116x4);
        EnumC1110q enumC1110q31 = new EnumC1110q("ENUM_LIST", 30, 30, 2, enumC1116x9);
        EnumC1110q enumC1110q32 = new EnumC1110q("SFIXED32_LIST", 31, 31, 2, enumC1116x4);
        EnumC1110q enumC1110q33 = new EnumC1110q("SFIXED64_LIST", 32, 32, 2, enumC1116x3);
        EnumC1110q enumC1110q34 = new EnumC1110q("SINT32_LIST", 33, 33, 2, enumC1116x4);
        EnumC1110q enumC1110q35 = new EnumC1110q("SINT64_LIST", 34, 34, 2, enumC1116x3);
        EnumC1110q enumC1110q36 = new EnumC1110q("DOUBLE_LIST_PACKED", 35, 35, 3, enumC1116x);
        b = enumC1110q36;
        EnumC1110q enumC1110q37 = new EnumC1110q("FLOAT_LIST_PACKED", 36, 36, 3, enumC1116x2);
        EnumC1110q enumC1110q38 = new EnumC1110q("INT64_LIST_PACKED", 37, 37, 3, enumC1116x3);
        EnumC1110q enumC1110q39 = new EnumC1110q("UINT64_LIST_PACKED", 38, 38, 3, enumC1116x3);
        EnumC1110q enumC1110q40 = new EnumC1110q("INT32_LIST_PACKED", 39, 39, 3, enumC1116x4);
        EnumC1110q enumC1110q41 = new EnumC1110q("FIXED64_LIST_PACKED", 40, 40, 3, enumC1116x3);
        EnumC1110q enumC1110q42 = new EnumC1110q("FIXED32_LIST_PACKED", 41, 41, 3, enumC1116x4);
        EnumC1110q enumC1110q43 = new EnumC1110q("BOOL_LIST_PACKED", 42, 42, 3, enumC1116x5);
        EnumC1110q enumC1110q44 = new EnumC1110q("UINT32_LIST_PACKED", 43, 43, 3, enumC1116x4);
        EnumC1110q enumC1110q45 = new EnumC1110q("ENUM_LIST_PACKED", 44, 44, 3, enumC1116x9);
        EnumC1110q enumC1110q46 = new EnumC1110q("SFIXED32_LIST_PACKED", 45, 45, 3, enumC1116x4);
        EnumC1110q enumC1110q47 = new EnumC1110q("SFIXED64_LIST_PACKED", 46, 46, 3, enumC1116x3);
        EnumC1110q enumC1110q48 = new EnumC1110q("SINT32_LIST_PACKED", 47, 47, 3, enumC1116x4);
        EnumC1110q enumC1110q49 = new EnumC1110q("SINT64_LIST_PACKED", 48, 48, 3, enumC1116x3);
        c = enumC1110q49;
        e = new EnumC1110q[]{enumC1110q, enumC1110q2, enumC1110q3, enumC1110q4, enumC1110q5, enumC1110q6, enumC1110q7, enumC1110q8, enumC1110q9, enumC1110q10, enumC1110q11, enumC1110q12, enumC1110q13, enumC1110q14, enumC1110q15, enumC1110q16, enumC1110q17, enumC1110q18, enumC1110q19, enumC1110q20, enumC1110q21, enumC1110q22, enumC1110q23, enumC1110q24, enumC1110q25, enumC1110q26, enumC1110q27, enumC1110q28, enumC1110q29, enumC1110q30, enumC1110q31, enumC1110q32, enumC1110q33, enumC1110q34, enumC1110q35, enumC1110q36, enumC1110q37, enumC1110q38, enumC1110q39, enumC1110q40, enumC1110q41, enumC1110q42, enumC1110q43, enumC1110q44, enumC1110q45, enumC1110q46, enumC1110q47, enumC1110q48, enumC1110q49, new EnumC1110q("GROUP_LIST", 49, 49, 2, enumC1116x7), new EnumC1110q("MAP", 50, 50, 4, EnumC1116x.VOID)};
        EnumC1110q[] enumC1110qArrValues = values();
        d = new EnumC1110q[enumC1110qArrValues.length];
        for (EnumC1110q enumC1110q50 : enumC1110qArrValues) {
            d[enumC1110q50.a] = enumC1110q50;
        }
    }

    public EnumC1110q(String str, int i, int i2, int i3, EnumC1116x enumC1116x) {
        this.a = i2;
        int iK = AbstractC0147y.k(i3);
        if (iK == 1 || iK == 3) {
            enumC1116x.getClass();
        }
        if (i3 == 1) {
            enumC1116x.ordinal();
        }
    }

    public static EnumC1110q valueOf(String str) {
        return (EnumC1110q) Enum.valueOf(EnumC1110q.class, str);
    }

    public static EnumC1110q[] values() {
        return (EnumC1110q[]) e.clone();
    }
}

package com.google.protobuf;

/* JADX WARN: Enum visitor error
jadx.core.utils.exceptions.JadxRuntimeException: Init of enum field 'c' uses external variables
	at jadx.core.dex.visitors.EnumVisitor.createEnumFieldByConstructor(EnumVisitor.java:451)
	at jadx.core.dex.visitors.EnumVisitor.processEnumFieldByRegister(EnumVisitor.java:395)
	at jadx.core.dex.visitors.EnumVisitor.extractEnumFieldsFromFilledArray(EnumVisitor.java:324)
	at jadx.core.dex.visitors.EnumVisitor.extractEnumFieldsFromInsn(EnumVisitor.java:262)
	at jadx.core.dex.visitors.EnumVisitor.convertToEnum(EnumVisitor.java:151)
	at jadx.core.dex.visitors.EnumVisitor.visit(EnumVisitor.java:100)
 */
/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* loaded from: classes2.dex */
public class B0 {
    public static final B0 c;
    public static final x0 d;
    public static final y0 e;
    public static final z0 f;
    public static final /* synthetic */ B0[] g;
    public final C0 a;
    public final int b;

    /* JADX INFO: Fake field, exist only in values array */
    B0 EF10;

    /* JADX INFO: Fake field, exist only in values array */
    B0 EF11;

    static {
        B0 b0 = new B0("DOUBLE", 0, C0.DOUBLE, 1);
        B0 b02 = new B0("FLOAT", 1, C0.FLOAT, 5);
        C0 c0 = C0.LONG;
        B0 b03 = new B0("INT64", 2, c0, 0);
        c = b03;
        B0 b04 = new B0("UINT64", 3, c0, 0);
        C0 c02 = C0.INT;
        B0 b05 = new B0("INT32", 4, c02, 0);
        B0 b06 = new B0("FIXED64", 5, c0, 1);
        B0 b07 = new B0("FIXED32", 6, c02, 5);
        B0 b08 = new B0("BOOL", 7, C0.BOOLEAN, 0);
        x0 x0Var = new x0("STRING", 8, C0.STRING, 2);
        d = x0Var;
        C0 c03 = C0.MESSAGE;
        y0 y0Var = new y0("GROUP", 9, c03, 3);
        e = y0Var;
        z0 z0Var = new z0("MESSAGE", 10, c03, 2);
        f = z0Var;
        g = new B0[]{b0, b02, b03, b04, b05, b06, b07, b08, x0Var, y0Var, z0Var, new A0("BYTES", 11, C0.BYTE_STRING, 2), new B0("UINT32", 12, c02, 0), new B0("ENUM", 13, C0.ENUM, 0), new B0("SFIXED32", 14, c02, 5), new B0("SFIXED64", 15, c0, 1), new B0("SINT32", 16, c02, 0), new B0("SINT64", 17, c0, 0)};
    }

    public B0(String str, int i, C0 c0, int i2) {
        this.a = c0;
        this.b = i2;
    }

    public static B0 valueOf(String str) {
        return (B0) Enum.valueOf(B0.class, str);
    }

    public static B0[] values() {
        return (B0[]) g.clone();
    }
}

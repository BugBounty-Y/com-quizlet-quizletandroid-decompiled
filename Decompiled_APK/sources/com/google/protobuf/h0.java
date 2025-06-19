package com.google.protobuf;

/* loaded from: classes2.dex */
public abstract class h0 {
    public static final f0 a = new f0();
    public static final g0 b = new g0();

    public static String c(C4012f c4012f) {
        StringBuilder sb = new StringBuilder(c4012f.size());
        for (int i = 0; i < c4012f.size(); i++) {
            byte bA = c4012f.a(i);
            if (bA == 34) {
                sb.append("\\\"");
            } else if (bA == 39) {
                sb.append("\\'");
            } else if (bA != 92) {
                switch (bA) {
                    case 7:
                        sb.append("\\a");
                        break;
                    case 8:
                        sb.append("\\b");
                        break;
                    case 9:
                        sb.append("\\t");
                        break;
                    case 10:
                        sb.append("\\n");
                        break;
                    case 11:
                        sb.append("\\v");
                        break;
                    case 12:
                        sb.append("\\f");
                        break;
                    case 13:
                        sb.append("\\r");
                        break;
                    default:
                        if (bA < 32 || bA > 126) {
                            sb.append('\\');
                            sb.append((char) (((bA >>> 6) & 3) + 48));
                            sb.append((char) (((bA >>> 3) & 7) + 48));
                            sb.append((char) ((bA & 7) + 48));
                            break;
                        } else {
                            sb.append((char) bA);
                            break;
                        }
                }
            } else {
                sb.append("\\\\");
            }
        }
        return sb.toString();
    }

    public static boolean d(byte b2) {
        return b2 > -65;
    }

    public abstract String a(int i, byte[] bArr, int i2);

    public abstract int b(String str, byte[] bArr, int i, int i2);

    public abstract int e(int i, byte[] bArr, int i2);

    public abstract void f(int i, byte[] bArr, int i2);
}

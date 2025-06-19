package androidx.compose.ui.text;

import androidx.compose.ui.graphics.C0861v;
import com.google.android.gms.internal.mlkit_vision_barcode.S5;
import com.google.android.gms.internal.mlkit_vision_barcode.V5;

/* loaded from: classes.dex */
public abstract class E {
    public static final long a = S5.g(14);
    public static final long b = S5.g(0);
    public static final long c = C0861v.f;
    public static final androidx.compose.ui.text.style.n d;

    static {
        long j = C0861v.b;
        d = j != 16 ? new androidx.compose.ui.text.style.c(j) : androidx.compose.ui.text.style.l.a;
    }

    /* JADX WARN: Removed duplicated region for block: B:102:0x0179  */
    /* JADX WARN: Removed duplicated region for block: B:106:0x0180  */
    /* JADX WARN: Removed duplicated region for block: B:110:0x0188  */
    /* JADX WARN: Removed duplicated region for block: B:113:0x0195  */
    /* JADX WARN: Removed duplicated region for block: B:115:0x019e  */
    /* JADX WARN: Removed duplicated region for block: B:116:0x01a1  */
    /* JADX WARN: Removed duplicated region for block: B:120:0x01aa  */
    /* JADX WARN: Removed duplicated region for block: B:122:0x01af  */
    /* JADX WARN: Removed duplicated region for block: B:123:0x01b2  */
    /* JADX WARN: Removed duplicated region for block: B:125:0x01b6  */
    /* JADX WARN: Removed duplicated region for block: B:126:0x01b9  */
    /* JADX WARN: Removed duplicated region for block: B:128:0x01bd  */
    /* JADX WARN: Removed duplicated region for block: B:129:0x01c0  */
    /* JADX WARN: Removed duplicated region for block: B:131:0x01c4  */
    /* JADX WARN: Removed duplicated region for block: B:134:0x01cc  */
    /* JADX WARN: Removed duplicated region for block: B:135:0x01d3  */
    /* JADX WARN: Removed duplicated region for block: B:137:0x01db  */
    /* JADX WARN: Removed duplicated region for block: B:139:0x01df  */
    /* JADX WARN: Removed duplicated region for block: B:140:0x01e2  */
    /* JADX WARN: Removed duplicated region for block: B:142:0x01e5  */
    /* JADX WARN: Removed duplicated region for block: B:143:0x01e8  */
    /* JADX WARN: Removed duplicated region for block: B:147:0x01ef  */
    /* JADX WARN: Removed duplicated region for block: B:149:0x01f3  */
    /* JADX WARN: Removed duplicated region for block: B:152:0x01f9  */
    /* JADX WARN: Removed duplicated region for block: B:153:0x01fc  */
    /* JADX WARN: Removed duplicated region for block: B:156:0x0202  */
    /* JADX WARN: Removed duplicated region for block: B:158:0x0206  */
    /* JADX WARN: Removed duplicated region for block: B:159:0x0209  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0029 A[PHI: r11
  0x0029: PHI (r11v8 long) = 
  (r11v1 long)
  (r11v1 long)
  (r11v1 long)
  (r11v1 long)
  (r11v1 long)
  (r11v1 long)
  (r11v1 long)
  (r11v1 long)
  (r11v1 long)
  (r11v1 long)
  (r11v1 long)
  (r11v9 long)
 binds: [B:36:0x0088, B:48:0x00b2, B:45:0x00a8, B:42:0x009e, B:39:0x0094, B:34:0x007c, B:29:0x006f, B:25:0x005f, B:22:0x0059, B:19:0x004f, B:16:0x0045, B:5:0x0026] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:80:0x010b  */
    /* JADX WARN: Removed duplicated region for block: B:85:0x0124  */
    /* JADX WARN: Removed duplicated region for block: B:91:0x013b  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final androidx.compose.ui.text.D a(androidx.compose.ui.text.D r19, long r20, androidx.compose.ui.graphics.AbstractC0857q r22, float r23, long r24, androidx.compose.ui.text.font.u r26, androidx.compose.ui.text.font.q r27, androidx.compose.ui.text.font.r r28, androidx.compose.ui.text.font.j r29, java.lang.String r30, long r31, androidx.compose.ui.text.style.a r33, androidx.compose.ui.text.style.o r34, androidx.compose.ui.text.intl.b r35, long r36, androidx.compose.ui.text.style.j r38, androidx.compose.ui.graphics.U r39, androidx.compose.ui.text.x r40, androidx.compose.ui.graphics.drawscope.e r41) {
        /*
            Method dump skipped, instructions count: 560
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.text.E.a(androidx.compose.ui.text.D, long, androidx.compose.ui.graphics.q, float, long, androidx.compose.ui.text.font.u, androidx.compose.ui.text.font.q, androidx.compose.ui.text.font.r, androidx.compose.ui.text.font.j, java.lang.String, long, androidx.compose.ui.text.style.a, androidx.compose.ui.text.style.o, androidx.compose.ui.text.intl.b, long, androidx.compose.ui.text.style.j, androidx.compose.ui.graphics.U, androidx.compose.ui.text.x, androidx.compose.ui.graphics.drawscope.e):androidx.compose.ui.text.D");
    }

    public static final Object b(float f, Object obj, Object obj2) {
        return ((double) f) < 0.5d ? obj : obj2;
    }

    public static final long c(long j, long j2, float f) {
        if (S5.h(j) || S5.h(j2)) {
            return ((androidx.compose.ui.unit.m) b(f, new androidx.compose.ui.unit.m(j), new androidx.compose.ui.unit.m(j2))).a;
        }
        if (S5.h(j) || S5.h(j2)) {
            throw new IllegalArgumentException("Cannot perform operation for Unspecified type.");
        }
        if (androidx.compose.ui.unit.n.a(androidx.compose.ui.unit.m.b(j), androidx.compose.ui.unit.m.b(j2))) {
            return S5.i(1095216660480L & j, V5.c(androidx.compose.ui.unit.m.c(j), androidx.compose.ui.unit.m.c(j2), f));
        }
        throw new IllegalArgumentException(("Cannot perform operation for " + ((Object) androidx.compose.ui.unit.n.b(androidx.compose.ui.unit.m.b(j))) + " and " + ((Object) androidx.compose.ui.unit.n.b(androidx.compose.ui.unit.m.b(j2)))).toString());
    }
}

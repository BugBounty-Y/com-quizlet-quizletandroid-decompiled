package androidx.compose.ui.window;

import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager;
import androidx.compose.runtime.B;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_barcode.P5;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public abstract class l {
    public static final B a = new B(d.c);

    /* JADX WARN: Removed duplicated region for block: B:104:0x024c  */
    /* JADX WARN: Removed duplicated region for block: B:108:0x025e  */
    /* JADX WARN: Removed duplicated region for block: B:110:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:23:0x0041  */
    /* JADX WARN: Removed duplicated region for block: B:30:0x0051  */
    /* JADX WARN: Removed duplicated region for block: B:41:0x0072  */
    /* JADX WARN: Removed duplicated region for block: B:42:0x0074  */
    /* JADX WARN: Removed duplicated region for block: B:43:0x0076  */
    /* JADX WARN: Removed duplicated region for block: B:46:0x00cd  */
    /* JADX WARN: Removed duplicated region for block: B:47:0x00fa  */
    /* JADX WARN: Removed duplicated region for block: B:50:0x010d  */
    /* JADX WARN: Removed duplicated region for block: B:51:0x010f  */
    /* JADX WARN: Removed duplicated region for block: B:54:0x0118  */
    /* JADX WARN: Removed duplicated region for block: B:55:0x011a  */
    /* JADX WARN: Removed duplicated region for block: B:58:0x012d  */
    /* JADX WARN: Removed duplicated region for block: B:62:0x013d  */
    /* JADX WARN: Removed duplicated region for block: B:66:0x0164  */
    /* JADX WARN: Removed duplicated region for block: B:67:0x0166  */
    /* JADX WARN: Removed duplicated region for block: B:70:0x016d  */
    /* JADX WARN: Removed duplicated region for block: B:71:0x016f  */
    /* JADX WARN: Removed duplicated region for block: B:74:0x0182 A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:75:0x0184  */
    /* JADX WARN: Removed duplicated region for block: B:78:0x01a1  */
    /* JADX WARN: Removed duplicated region for block: B:79:0x01a3  */
    /* JADX WARN: Removed duplicated region for block: B:83:0x01af  */
    /* JADX WARN: Removed duplicated region for block: B:87:0x01c9  */
    /* JADX WARN: Removed duplicated region for block: B:91:0x01e4  */
    /* JADX WARN: Removed duplicated region for block: B:95:0x0204  */
    /* JADX WARN: Removed duplicated region for block: B:98:0x0227  */
    /* JADX WARN: Removed duplicated region for block: B:99:0x022b  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void a(androidx.compose.ui.window.x r24, kotlin.jvm.functions.Function0 r25, androidx.compose.ui.window.y r26, androidx.compose.runtime.internal.d r27, androidx.compose.runtime.InterfaceC0806l r28, int r29, int r30) {
        /*
            Method dump skipped, instructions count: 620
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.window.l.a(androidx.compose.ui.window.x, kotlin.jvm.functions.Function0, androidx.compose.ui.window.y, androidx.compose.runtime.internal.d, androidx.compose.runtime.l, int, int):void");
    }

    public static final void b(androidx.compose.ui.i iVar, long j, Function0 function0, y yVar, androidx.compose.runtime.internal.d dVar, InterfaceC0806l interfaceC0806l, int i, int i2) {
        long j2;
        androidx.compose.ui.i iVar2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(295309329);
        int i3 = i | 54;
        int i4 = i2 & 4;
        if (i4 != 0) {
            i3 = i | 438;
        } else if ((i & 384) == 0) {
            i3 |= c0814p.h(function0) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i3 |= c0814p.f(yVar) ? 2048 : 1024;
        }
        if ((i3 & 9363) == 9362 && c0814p.x()) {
            c0814p.Q();
            iVar2 = iVar;
            j2 = j;
        } else {
            androidx.compose.ui.i iVar3 = androidx.compose.ui.b.a;
            long jB = P5.b(0, 0);
            if (i4 != 0) {
                function0 = null;
            }
            Function0 function02 = function0;
            Object objI = c0814p.I();
            if (objI == C0804k.a) {
                objI = new a(jB);
                c0814p.i0(objI);
            }
            a((a) objI, function02, yVar, dVar, c0814p, (i3 >> 3) & 8176, 0);
            function0 = function02;
            j2 = jB;
            iVar2 = iVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new f(iVar2, j2, function0, yVar, dVar, i, i2);
        }
    }

    public static final boolean c(View view) {
        ViewGroup.LayoutParams layoutParams = view.getRootView().getLayoutParams();
        WindowManager.LayoutParams layoutParams2 = layoutParams instanceof WindowManager.LayoutParams ? (WindowManager.LayoutParams) layoutParams : null;
        return (layoutParams2 == null || (layoutParams2.flags & 8192) == 0) ? false : true;
    }
}

package androidx.compose.foundation.text.input.internal;

import android.graphics.PointF;
import android.os.CancellationSignal;
import android.view.inputmethod.DeleteGesture;
import android.view.inputmethod.DeleteRangeGesture;
import android.view.inputmethod.HandwritingGesture;
import android.view.inputmethod.InsertGesture;
import android.view.inputmethod.JoinOrSplitGesture;
import android.view.inputmethod.PreviewableHandwritingGesture;
import android.view.inputmethod.RemoveSpaceGesture;
import android.view.inputmethod.SelectGesture;
import android.view.inputmethod.SelectRangeGesture;
import androidx.compose.animation.C0278e;
import androidx.compose.foundation.text.C0492h0;
import androidx.compose.foundation.text.K0;
import androidx.compose.foundation.text.V;
import androidx.compose.foundation.text.selection.i0;
import androidx.compose.ui.platform.Y0;
import androidx.compose.ui.text.C0995g;
import androidx.compose.ui.text.G;
import androidx.compose.ui.text.H;
import androidx.compose.ui.text.K;
import androidx.compose.ui.text.input.C0998a;
import androidx.compose.ui.text.input.C1004g;
import androidx.compose.ui.text.input.InterfaceC1006i;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3205m5;
import com.google.android.gms.internal.mlkit_vision_barcode.Q4;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Regex;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class s {
    public static final s a = new s();

    private final void C(C0492h0 c0492h0, SelectGesture selectGesture, i0 i0Var) {
        if (i0Var != null) {
            long jF = x.f(c0492h0, androidx.compose.ui.graphics.F.D(selectGesture.getSelectionArea()), G(selectGesture.getGranularity()));
            C0492h0 c0492h02 = i0Var.d;
            if (c0492h02 != null) {
                c0492h02.f(jF);
            }
            C0492h0 c0492h03 = i0Var.d;
            if (c0492h03 != null) {
                c0492h03.e(K.b);
            }
            if (K.b(jF)) {
                return;
            }
            i0Var.r(false);
            i0Var.p(V.a);
        }
    }

    private final void D(F f, SelectGesture selectGesture, E e) {
        androidx.compose.ui.graphics.F.D(selectGesture.getSelectionArea());
        G(selectGesture.getGranularity());
        throw null;
    }

    private final void E(C0492h0 c0492h0, SelectRangeGesture selectRangeGesture, i0 i0Var) {
        if (i0Var != null) {
            long jA = x.a(c0492h0, androidx.compose.ui.graphics.F.D(selectRangeGesture.getSelectionStartArea()), androidx.compose.ui.graphics.F.D(selectRangeGesture.getSelectionEndArea()), G(selectRangeGesture.getGranularity()));
            C0492h0 c0492h02 = i0Var.d;
            if (c0492h02 != null) {
                c0492h02.f(jA);
            }
            C0492h0 c0492h03 = i0Var.d;
            if (c0492h03 != null) {
                c0492h03.e(K.b);
            }
            if (K.b(jA)) {
                return;
            }
            i0Var.r(false);
            i0Var.p(V.a);
        }
    }

    private final void F(F f, SelectRangeGesture selectRangeGesture, E e) {
        androidx.compose.ui.graphics.F.D(selectRangeGesture.getSelectionStartArea());
        androidx.compose.ui.graphics.F.D(selectRangeGesture.getSelectionEndArea());
        G(selectRangeGesture.getGranularity());
        throw null;
    }

    private final int G(int i) {
        return i != 1 ? 0 : 1;
    }

    private final int a(F f, HandwritingGesture handwritingGesture) {
        throw null;
    }

    private final int b(HandwritingGesture handwritingGesture, Function1<? super InterfaceC1006i, Unit> function1) {
        String fallbackText = handwritingGesture.getFallbackText();
        if (fallbackText == null) {
            return 3;
        }
        function1.invoke(new C0998a(fallbackText, 1));
        return 5;
    }

    private final int c(C0492h0 c0492h0, DeleteGesture deleteGesture, C0995g c0995g, Function1<? super InterfaceC1006i, Unit> function1) {
        int iG = G(deleteGesture.getGranularity());
        long jF = x.f(c0492h0, androidx.compose.ui.graphics.F.D(deleteGesture.getDeletionArea()), iG);
        if (K.b(jF)) {
            return a.b(p.q(deleteGesture), function1);
        }
        h(jF, c0995g, iG == 1, function1);
        return 1;
    }

    private final int d(F f, DeleteGesture deleteGesture, E e) {
        G(deleteGesture.getGranularity());
        androidx.compose.ui.graphics.F.D(deleteGesture.getDeletionArea());
        throw null;
    }

    private final int e(C0492h0 c0492h0, DeleteRangeGesture deleteRangeGesture, C0995g c0995g, Function1<? super InterfaceC1006i, Unit> function1) {
        int iG = G(deleteRangeGesture.getGranularity());
        long jA = x.a(c0492h0, androidx.compose.ui.graphics.F.D(deleteRangeGesture.getDeletionStartArea()), androidx.compose.ui.graphics.F.D(deleteRangeGesture.getDeletionEndArea()), iG);
        if (K.b(jA)) {
            return a.b(p.q(deleteRangeGesture), function1);
        }
        h(jA, c0995g, iG == 1, function1);
        return 1;
    }

    private final int f(F f, DeleteRangeGesture deleteRangeGesture, E e) {
        G(deleteRangeGesture.getGranularity());
        androidx.compose.ui.graphics.F.D(deleteRangeGesture.getDeletionStartArea());
        androidx.compose.ui.graphics.F.D(deleteRangeGesture.getDeletionEndArea());
        throw null;
    }

    private final void g(F f, long j, boolean z) {
        if (!z) {
            throw null;
        }
        throw null;
    }

    private final void h(long j, C0995g c0995g, boolean z, Function1<? super InterfaceC1006i, Unit> function1) {
        if (z) {
            int i = K.c;
            int iCharCount = (int) (j >> 32);
            int iCharCount2 = (int) (j & 4294967295L);
            int iCodePointBefore = iCharCount > 0 ? Character.codePointBefore(c0995g, iCharCount) : 10;
            int iCodePointAt = iCharCount2 < c0995g.a.length() ? Character.codePointAt(c0995g, iCharCount2) : 10;
            if (x.i(iCodePointBefore) && (x.h(iCodePointAt) || x.g(iCodePointAt))) {
                do {
                    iCharCount -= Character.charCount(iCodePointBefore);
                    if (iCharCount == 0) {
                        break;
                    } else {
                        iCodePointBefore = Character.codePointBefore(c0995g, iCharCount);
                    }
                } while (x.i(iCodePointBefore));
                j = AbstractC3205m5.c(iCharCount, iCharCount2);
            } else if (x.i(iCodePointAt) && (x.h(iCodePointBefore) || x.g(iCodePointBefore))) {
                do {
                    iCharCount2 += Character.charCount(iCodePointAt);
                    if (iCharCount2 == c0995g.a.length()) {
                        break;
                    } else {
                        iCodePointAt = Character.codePointAt(c0995g, iCharCount2);
                    }
                } while (x.i(iCodePointAt));
                j = AbstractC3205m5.c(iCharCount, iCharCount2);
            }
        }
        int i2 = (int) (4294967295L & j);
        function1.invoke(new t(new InterfaceC1006i[]{new androidx.compose.ui.text.input.y(i2, i2), new C1004g(K.c(j), 0)}));
    }

    /* JADX WARN: Removed duplicated region for block: B:13:0x0049  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private final int k(androidx.compose.foundation.text.C0492h0 r7, android.view.inputmethod.InsertGesture r8, androidx.compose.ui.platform.Y0 r9, kotlin.jvm.functions.Function1<? super androidx.compose.ui.text.input.InterfaceC1006i, kotlin.Unit> r10) {
        /*
            r6 = this;
            if (r9 != 0) goto Lb
            android.view.inputmethod.HandwritingGesture r7 = androidx.compose.foundation.text.input.internal.p.q(r8)
            int r7 = r6.b(r7, r10)
            return r7
        Lb:
            android.graphics.PointF r0 = androidx.compose.foundation.text.input.internal.p.j(r8)
            float r1 = r0.x
            float r0 = r0.y
            long r0 = com.google.android.gms.internal.mlkit_vision_barcode.Q4.c(r1, r0)
            androidx.compose.foundation.text.K0 r2 = r7.d()
            r3 = 1
            r4 = -1
            if (r2 == 0) goto L49
            androidx.compose.ui.text.H r2 = r2.a
            androidx.compose.ui.text.o r2 = r2.b
            androidx.compose.ui.layout.r r5 = r7.c()
            if (r5 == 0) goto L49
            long r0 = r5.N(r0)
            int r9 = androidx.compose.foundation.text.input.internal.x.e(r2, r0, r9)
            if (r9 != r4) goto L34
            goto L49
        L34:
            float r5 = r2.d(r9)
            float r9 = r2.b(r9)
            float r9 = r9 + r5
            r5 = 1073741824(0x40000000, float:2.0)
            float r9 = r9 / r5
            long r0 = androidx.compose.ui.geometry.b.a(r9, r3, r0)
            int r9 = r2.e(r0)
            goto L4a
        L49:
            r9 = r4
        L4a:
            if (r9 == r4) goto L63
            androidx.compose.foundation.text.K0 r7 = r7.d()
            if (r7 == 0) goto L5b
            androidx.compose.ui.text.H r7 = r7.a
            boolean r7 = androidx.compose.foundation.text.input.internal.x.b(r7, r9)
            if (r7 != r3) goto L5b
            goto L63
        L5b:
            java.lang.String r7 = androidx.compose.foundation.text.input.internal.p.v(r8)
            r6.m(r9, r7, r10)
            return r3
        L63:
            android.view.inputmethod.HandwritingGesture r7 = androidx.compose.foundation.text.input.internal.p.q(r8)
            int r7 = r6.b(r7, r10)
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.text.input.internal.s.k(androidx.compose.foundation.text.h0, android.view.inputmethod.InsertGesture, androidx.compose.ui.platform.Y0, kotlin.jvm.functions.Function1):int");
    }

    private final int l(F f, InsertGesture insertGesture, E e, Y0 y0) {
        PointF insertionPoint = insertGesture.getInsertionPoint();
        Q4.c(insertionPoint.x, insertionPoint.y);
        throw null;
    }

    private final void m(int i, String str, Function1<? super InterfaceC1006i, Unit> function1) {
        function1.invoke(new t(new InterfaceC1006i[]{new androidx.compose.ui.text.input.y(i, i), new C0998a(str, 1)}));
    }

    /* JADX WARN: Removed duplicated region for block: B:13:0x0049  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private final int n(androidx.compose.foundation.text.C0492h0 r11, android.view.inputmethod.JoinOrSplitGesture r12, androidx.compose.ui.text.C0995g r13, androidx.compose.ui.platform.Y0 r14, kotlin.jvm.functions.Function1<? super androidx.compose.ui.text.input.InterfaceC1006i, kotlin.Unit> r15) {
        /*
            r10 = this;
            if (r14 != 0) goto Lb
            android.view.inputmethod.HandwritingGesture r11 = androidx.compose.foundation.text.input.internal.p.q(r12)
            int r11 = r10.b(r11, r15)
            return r11
        Lb:
            android.graphics.PointF r0 = androidx.compose.foundation.text.input.internal.p.k(r12)
            float r1 = r0.x
            float r0 = r0.y
            long r0 = com.google.android.gms.internal.mlkit_vision_barcode.Q4.c(r1, r0)
            androidx.compose.foundation.text.K0 r2 = r11.d()
            r3 = 1
            r4 = -1
            if (r2 == 0) goto L49
            androidx.compose.ui.text.H r2 = r2.a
            androidx.compose.ui.text.o r2 = r2.b
            androidx.compose.ui.layout.r r5 = r11.c()
            if (r5 == 0) goto L49
            long r0 = r5.N(r0)
            int r14 = androidx.compose.foundation.text.input.internal.x.e(r2, r0, r14)
            if (r14 != r4) goto L34
            goto L49
        L34:
            float r5 = r2.d(r14)
            float r14 = r2.b(r14)
            float r14 = r14 + r5
            r5 = 1073741824(0x40000000, float:2.0)
            float r14 = r14 / r5
            long r0 = androidx.compose.ui.geometry.b.a(r14, r3, r0)
            int r14 = r2.e(r0)
            goto L4a
        L49:
            r14 = r4
        L4a:
            if (r14 == r4) goto L5a
            androidx.compose.foundation.text.K0 r11 = r11.d()
            if (r11 == 0) goto L5d
            androidx.compose.ui.text.H r11 = r11.a
            boolean r11 = androidx.compose.foundation.text.input.internal.x.b(r11, r14)
            if (r11 != r3) goto L5d
        L5a:
            r4 = r10
            r9 = r15
            goto La7
        L5d:
            r11 = r14
        L5e:
            if (r11 <= 0) goto L71
            int r12 = java.lang.Character.codePointBefore(r13, r11)
            boolean r0 = androidx.compose.foundation.text.input.internal.x.h(r12)
            if (r0 != 0) goto L6b
            goto L71
        L6b:
            int r12 = java.lang.Character.charCount(r12)
            int r11 = r11 - r12
            goto L5e
        L71:
            java.lang.String r12 = r13.a
            int r12 = r12.length()
            if (r14 >= r12) goto L8a
            int r12 = java.lang.Character.codePointAt(r13, r14)
            boolean r0 = androidx.compose.foundation.text.input.internal.x.h(r12)
            if (r0 != 0) goto L84
            goto L8a
        L84:
            int r12 = java.lang.Character.charCount(r12)
            int r14 = r14 + r12
            goto L71
        L8a:
            long r5 = com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3205m5.c(r11, r14)
            boolean r11 = androidx.compose.ui.text.K.b(r5)
            if (r11 == 0) goto L9f
            r11 = 32
            long r11 = r5 >> r11
            int r11 = (int) r11
            java.lang.String r12 = " "
            r10.m(r11, r12, r15)
            return r3
        L9f:
            r8 = 0
            r4 = r10
            r7 = r13
            r9 = r15
            r4.h(r5, r7, r8, r9)
            return r3
        La7:
            android.view.inputmethod.HandwritingGesture r11 = androidx.compose.foundation.text.input.internal.p.q(r12)
            int r11 = r10.b(r11, r9)
            return r11
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.text.input.internal.s.n(androidx.compose.foundation.text.h0, android.view.inputmethod.JoinOrSplitGesture, androidx.compose.ui.text.g, androidx.compose.ui.platform.Y0, kotlin.jvm.functions.Function1):int");
    }

    private final int o(F f, JoinOrSplitGesture joinOrSplitGesture, E e, Y0 y0) {
        throw null;
    }

    private final int p(C0492h0 c0492h0, RemoveSpaceGesture removeSpaceGesture, C0995g c0995g, Y0 y0, Function1<? super InterfaceC1006i, Unit> function1) {
        long jF;
        int i;
        K0 k0D = c0492h0.d();
        H h = k0D != null ? k0D.a : null;
        PointF startPoint = removeSpaceGesture.getStartPoint();
        long jC = Q4.c(startPoint.x, startPoint.y);
        PointF endPoint = removeSpaceGesture.getEndPoint();
        long jC2 = Q4.c(endPoint.x, endPoint.y);
        androidx.compose.ui.layout.r rVarC = c0492h0.c();
        if (h == null || rVarC == null) {
            jF = K.b;
        } else {
            long jN = rVarC.N(jC);
            long jN2 = rVarC.N(jC2);
            androidx.compose.ui.text.o oVar = h.b;
            int iE = x.e(oVar, jN, y0);
            int iE2 = x.e(oVar, jN2, y0);
            if (iE != -1) {
                if (iE2 != -1) {
                    iE = Math.min(iE, iE2);
                }
                iE2 = iE;
            } else if (iE2 == -1) {
                jF = K.b;
            }
            float fB = (oVar.b(iE2) + oVar.d(iE2)) / 2;
            jF = oVar.f(new androidx.compose.ui.geometry.c(Math.min(androidx.compose.ui.geometry.b.d(jN), androidx.compose.ui.geometry.b.d(jN2)), fB - 0.1f, Math.max(androidx.compose.ui.geometry.b.d(jN), androidx.compose.ui.geometry.b.d(jN2)), fB + 0.1f), 0, androidx.compose.ui.text.F.a);
        }
        if (K.b(jF)) {
            return a.b(p.q(removeSpaceGesture), function1);
        }
        kotlin.jvm.internal.H h2 = new kotlin.jvm.internal.H();
        h2.a = -1;
        kotlin.jvm.internal.H h3 = new kotlin.jvm.internal.H();
        h3.a = -1;
        String strF = new Regex("\\s+").f(c0995g.subSequence(K.e(jF), K.d(jF)).a, new C0278e(26, h2, h3));
        int i2 = h2.a;
        if (i2 == -1 || (i = h3.a) == -1) {
            return b(p.q(removeSpaceGesture), function1);
        }
        int i3 = (int) (jF >> 32);
        String strSubstring = strF.substring(i2, strF.length() - (K.c(jF) - h3.a));
        Intrinsics.checkNotNullExpressionValue(strSubstring, "this as java.lang.String…ing(startIndex, endIndex)");
        function1.invoke(new t(new InterfaceC1006i[]{new androidx.compose.ui.text.input.y(i3 + i2, i3 + i), new C0998a(strSubstring, 1)}));
        return 1;
    }

    private final int q(F f, RemoveSpaceGesture removeSpaceGesture, E e, Y0 y0) {
        throw null;
    }

    private final int r(C0492h0 c0492h0, SelectGesture selectGesture, i0 i0Var, Function1<? super InterfaceC1006i, Unit> function1) {
        long jF = x.f(c0492h0, androidx.compose.ui.graphics.F.D(selectGesture.getSelectionArea()), G(selectGesture.getGranularity()));
        if (K.b(jF)) {
            return a.b(p.q(selectGesture), function1);
        }
        v(jF, i0Var, function1);
        return 1;
    }

    private final int s(F f, SelectGesture selectGesture, E e) {
        androidx.compose.ui.graphics.F.D(selectGesture.getSelectionArea());
        G(selectGesture.getGranularity());
        throw null;
    }

    private final int t(C0492h0 c0492h0, SelectRangeGesture selectRangeGesture, i0 i0Var, Function1<? super InterfaceC1006i, Unit> function1) {
        long jA = x.a(c0492h0, androidx.compose.ui.graphics.F.D(selectRangeGesture.getSelectionStartArea()), androidx.compose.ui.graphics.F.D(selectRangeGesture.getSelectionEndArea()), G(selectRangeGesture.getGranularity()));
        if (K.b(jA)) {
            return a.b(p.q(selectRangeGesture), function1);
        }
        v(jA, i0Var, function1);
        return 1;
    }

    private final int u(F f, SelectRangeGesture selectRangeGesture, E e) {
        androidx.compose.ui.graphics.F.D(selectRangeGesture.getSelectionStartArea());
        androidx.compose.ui.graphics.F.D(selectRangeGesture.getSelectionEndArea());
        G(selectRangeGesture.getGranularity());
        throw null;
    }

    private final void v(long j, i0 i0Var, Function1<? super InterfaceC1006i, Unit> function1) {
        int i = K.c;
        function1.invoke(new androidx.compose.ui.text.input.y((int) (j >> 32), (int) (j & 4294967295L)));
        if (i0Var != null) {
            i0Var.h(true);
        }
    }

    private final void w(C0492h0 c0492h0, DeleteGesture deleteGesture, i0 i0Var) {
        if (i0Var != null) {
            long jF = x.f(c0492h0, androidx.compose.ui.graphics.F.D(deleteGesture.getDeletionArea()), G(deleteGesture.getGranularity()));
            C0492h0 c0492h02 = i0Var.d;
            if (c0492h02 != null) {
                c0492h02.e(jF);
            }
            C0492h0 c0492h03 = i0Var.d;
            if (c0492h03 != null) {
                c0492h03.f(K.b);
            }
            if (K.b(jF)) {
                return;
            }
            i0Var.r(false);
            i0Var.p(V.a);
        }
    }

    private final void x(F f, DeleteGesture deleteGesture, E e) {
        androidx.compose.ui.graphics.F.D(deleteGesture.getDeletionArea());
        G(deleteGesture.getGranularity());
        throw null;
    }

    private final void y(C0492h0 c0492h0, DeleteRangeGesture deleteRangeGesture, i0 i0Var) {
        if (i0Var != null) {
            long jA = x.a(c0492h0, androidx.compose.ui.graphics.F.D(deleteRangeGesture.getDeletionStartArea()), androidx.compose.ui.graphics.F.D(deleteRangeGesture.getDeletionEndArea()), G(deleteRangeGesture.getGranularity()));
            C0492h0 c0492h02 = i0Var.d;
            if (c0492h02 != null) {
                c0492h02.e(jA);
            }
            C0492h0 c0492h03 = i0Var.d;
            if (c0492h03 != null) {
                c0492h03.f(K.b);
            }
            if (K.b(jA)) {
                return;
            }
            i0Var.r(false);
            i0Var.p(V.a);
        }
    }

    private final void z(F f, DeleteRangeGesture deleteRangeGesture, E e) {
        androidx.compose.ui.graphics.F.D(deleteRangeGesture.getDeletionStartArea());
        androidx.compose.ui.graphics.F.D(deleteRangeGesture.getDeletionEndArea());
        G(deleteRangeGesture.getGranularity());
        throw null;
    }

    public final boolean A(@NotNull C0492h0 c0492h0, @NotNull PreviewableHandwritingGesture previewableHandwritingGesture, i0 i0Var, CancellationSignal cancellationSignal) {
        G g;
        C0995g c0995g = c0492h0.j;
        if (c0995g == null) {
            return false;
        }
        K0 k0D = c0492h0.d();
        if (!c0995g.equals((k0D == null || (g = k0D.a.a) == null) ? null : g.a)) {
            return false;
        }
        if (p.y(previewableHandwritingGesture)) {
            C(c0492h0, p.r(previewableHandwritingGesture), i0Var);
        } else if (androidx.camera.camera2.internal.compat.j.r(previewableHandwritingGesture)) {
            w(c0492h0, androidx.camera.camera2.internal.compat.j.h(previewableHandwritingGesture), i0Var);
        } else if (androidx.camera.camera2.internal.compat.j.u(previewableHandwritingGesture)) {
            E(c0492h0, androidx.camera.camera2.internal.compat.j.m(previewableHandwritingGesture), i0Var);
        } else {
            if (!androidx.camera.camera2.internal.compat.j.w(previewableHandwritingGesture)) {
                return false;
            }
            y(c0492h0, androidx.camera.camera2.internal.compat.j.i(previewableHandwritingGesture), i0Var);
        }
        if (cancellationSignal == null) {
            return true;
        }
        cancellationSignal.setOnCancelListener(new q(i0Var, 0));
        return true;
    }

    public final boolean B(@NotNull F f, @NotNull PreviewableHandwritingGesture previewableHandwritingGesture, @NotNull E e, CancellationSignal cancellationSignal) {
        if (p.y(previewableHandwritingGesture)) {
            D(f, p.r(previewableHandwritingGesture), e);
        } else if (androidx.camera.camera2.internal.compat.j.r(previewableHandwritingGesture)) {
            x(f, androidx.camera.camera2.internal.compat.j.h(previewableHandwritingGesture), e);
        } else if (androidx.camera.camera2.internal.compat.j.u(previewableHandwritingGesture)) {
            F(f, androidx.camera.camera2.internal.compat.j.m(previewableHandwritingGesture), e);
        } else {
            if (!androidx.camera.camera2.internal.compat.j.w(previewableHandwritingGesture)) {
                return false;
            }
            z(f, androidx.camera.camera2.internal.compat.j.i(previewableHandwritingGesture), e);
        }
        if (cancellationSignal == null) {
            return true;
        }
        cancellationSignal.setOnCancelListener(new r());
        return true;
    }

    public final int i(@NotNull C0492h0 c0492h0, @NotNull HandwritingGesture handwritingGesture, i0 i0Var, Y0 y0, @NotNull Function1<? super InterfaceC1006i, Unit> function1) {
        G g;
        C0995g c0995g = c0492h0.j;
        if (c0995g == null) {
            return 3;
        }
        K0 k0D = c0492h0.d();
        if (!c0995g.equals((k0D == null || (g = k0D.a.a) == null) ? null : g.a)) {
            return 3;
        }
        if (p.y(handwritingGesture)) {
            return r(c0492h0, p.r(handwritingGesture), i0Var, function1);
        }
        if (androidx.camera.camera2.internal.compat.j.r(handwritingGesture)) {
            return c(c0492h0, androidx.camera.camera2.internal.compat.j.h(handwritingGesture), c0995g, function1);
        }
        if (androidx.camera.camera2.internal.compat.j.u(handwritingGesture)) {
            return t(c0492h0, androidx.camera.camera2.internal.compat.j.m(handwritingGesture), i0Var, function1);
        }
        if (androidx.camera.camera2.internal.compat.j.w(handwritingGesture)) {
            return e(c0492h0, androidx.camera.camera2.internal.compat.j.i(handwritingGesture), c0995g, function1);
        }
        if (androidx.camera.camera2.internal.compat.j.C(handwritingGesture)) {
            return n(c0492h0, androidx.camera.camera2.internal.compat.j.k(handwritingGesture), c0995g, y0, function1);
        }
        if (androidx.camera.camera2.internal.compat.j.y(handwritingGesture)) {
            return k(c0492h0, androidx.camera.camera2.internal.compat.j.j(handwritingGesture), y0, function1);
        }
        if (androidx.camera.camera2.internal.compat.j.A(handwritingGesture)) {
            return p(c0492h0, androidx.camera.camera2.internal.compat.j.l(handwritingGesture), c0995g, y0, function1);
        }
        return 2;
    }

    public final int j(@NotNull F f, @NotNull HandwritingGesture handwritingGesture, @NotNull E e, Y0 y0) {
        if (p.y(handwritingGesture)) {
            return s(f, p.r(handwritingGesture), e);
        }
        if (androidx.camera.camera2.internal.compat.j.r(handwritingGesture)) {
            return d(f, androidx.camera.camera2.internal.compat.j.h(handwritingGesture), e);
        }
        if (androidx.camera.camera2.internal.compat.j.u(handwritingGesture)) {
            return u(f, androidx.camera.camera2.internal.compat.j.m(handwritingGesture), e);
        }
        if (androidx.camera.camera2.internal.compat.j.w(handwritingGesture)) {
            return f(f, androidx.camera.camera2.internal.compat.j.i(handwritingGesture), e);
        }
        if (androidx.camera.camera2.internal.compat.j.C(handwritingGesture)) {
            return o(f, androidx.camera.camera2.internal.compat.j.k(handwritingGesture), e, y0);
        }
        if (androidx.camera.camera2.internal.compat.j.y(handwritingGesture)) {
            return l(f, androidx.camera.camera2.internal.compat.j.j(handwritingGesture), e, y0);
        }
        if (androidx.camera.camera2.internal.compat.j.A(handwritingGesture)) {
            return q(f, androidx.camera.camera2.internal.compat.j.l(handwritingGesture), e, y0);
        }
        return 2;
    }
}

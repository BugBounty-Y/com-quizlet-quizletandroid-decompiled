package androidx.transition;

import android.graphics.Rect;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.E0;
import androidx.compose.foundation.layout.G0;
import androidx.compose.foundation.layout.I0;
import androidx.compose.foundation.layout.K0;
import androidx.compose.material3.Q4;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.graphics.C0861v;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3169i5;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3351i2;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3355j2;
import com.google.android.gms.internal.mlkit_vision_camera.O1;
import com.google.android.gms.internal.mlkit_vision_camera.R1;
import com.google.android.gms.internal.mlkit_vision_document_scanner.V4;
import com.google.android.gms.measurement.internal.Z;
import com.quizlet.assembly.compose.buttons.C4076a;
import com.quizlet.assembly.compose.buttons.C4078c;
import com.quizlet.data.model.R0;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.net.IDN;
import java.net.InetAddress;
import java.util.Locale;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import okio.C5091h;

/* renamed from: androidx.transition.h, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1405h {
    public final /* synthetic */ int a;
    public final /* synthetic */ Rect b;

    public /* synthetic */ C1405h(int i, Rect rect) {
        this.a = i;
        this.b = rect;
    }

    public static final void a(String str, com.quizlet.features.practicetest.results.data.d dVar, String str2, String str3, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-311958273);
        if ((i & 6) == 0) {
            i2 = (c0814p.f(str) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= (i & 64) == 0 ? c0814p.f(dVar) : c0814p.h(dVar) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.f(str2) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p.f(str3) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i2 |= c0814p.f(qVar) ? 16384 : 8192;
        }
        if ((i2 & 9363) == 9362 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVar);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, bA, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            Q4.b(str, null, ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.e(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p.j(com.quizlet.themes.w.a)).o, c0814p, i2 & 14, 0, 65530);
            c0814p = c0814p;
            c0814p.X(-2034340780);
            if (str2 != null) {
                O1.a(new R0(str2, str3), null, c0814p, 0);
            }
            c0814p.p(false);
            boolean z = dVar instanceof com.quizlet.features.practicetest.results.data.c;
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            if (z) {
                c0814p.X(1360246892);
                androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(nVar, "writtenQuestion");
                com.quizlet.themes.m.g.s();
                com.quizlet.features.practicetest.results.data.c cVar = (com.quizlet.features.practicetest.results.data.c) dVar;
                AbstractC3355j2.a(cVar.a, cVar.b, cVar.c, AbstractC0382e.y(qVarG, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.h, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), c0814p, 0);
                c0814p.p(false);
            } else if (dVar instanceof com.quizlet.features.practicetest.results.data.a) {
                c0814p.X(1360714837);
                androidx.compose.ui.q qVarG2 = androidx.compose.ui.platform.N.G(nVar, "multipleChoiceQuestion");
                com.quizlet.themes.m.g.s();
                com.quizlet.features.practicetest.results.data.a aVar = (com.quizlet.features.practicetest.results.data.a) dVar;
                AbstractC3351i2.a(aVar.a, aVar.b, aVar.d, aVar.c, AbstractC0382e.y(qVarG2, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.h, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), c0814p, 0);
                c0814p = c0814p;
                c0814p.p(false);
            } else {
                if (!(dVar instanceof com.quizlet.features.practicetest.results.data.b)) {
                    throw Z.j(-2034332247, c0814p, false);
                }
                c0814p.X(1361256004);
                com.quizlet.themes.m.g.u();
                R1.c(0, 0, c0814p, AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.g, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), AbstractC3106b5.d(c0814p, R.string.practice_test_results_not_available));
                c0814p.p(false);
            }
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.achievements.ui.composables.p(str, dVar, str2, str3, qVar, i, 8);
        }
    }

    public static final void b(String question, int i, com.quizlet.features.practicetest.results.data.d gradedAnswer, boolean z, androidx.compose.ui.q qVar, String str, String str2, Function0 function0, InterfaceC0806l interfaceC0806l, int i2) {
        boolean z2;
        Intrinsics.checkNotNullParameter(question, "question");
        Intrinsics.checkNotNullParameter(gradedAnswer, "gradedAnswer");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1039107193);
        int i3 = i2 | (c0814p.f(question) ? 4 : 2) | (c0814p.d(i) ? 32 : 16) | (c0814p.f(gradedAnswer) ? 256 : 128) | (c0814p.g(z) ? 2048 : 1024) | (c0814p.f(qVar) ? 16384 : 8192) | (c0814p.f(str) ? 131072 : 65536) | (c0814p.f(str2) ? 1048576 : 524288) | (c0814p.h(function0) ? 8388608 : 4194304);
        if ((4793491 & i3) == 4793490 && c0814p.x()) {
            c0814p.Q();
        } else {
            G0 g0B = E0.b(AbstractC0398m.a, androidx.compose.ui.b.j, c0814p, 0);
            int i4 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVar);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, g0B, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p, i4, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            I0 i0 = I0.a;
            Q4.b(AbstractC3106b5.c(R.string.practice_test_question_number, new Object[]{Integer.valueOf(i)}, c0814p), null, AbstractC3169i5.f(c0814p).b.e(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, AbstractC3169i5.g(c0814p).o, c0814p, 0, 0, 65530);
            c0814p = c0814p;
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            if (z) {
                c0814p.X(-599143197);
                androidx.compose.ui.q qVarA = i0.a(nVar, 1.0f, true);
                com.quizlet.themes.m.g.w();
                z2 = true;
                Q4.b(AbstractC3106b5.d(c0814p, R.string.practice_test_question_removed), AbstractC0382e.y(qVarA, com.quizlet.ui.resources.designsystem.generated.j.f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 14), AbstractC3169i5.f(c0814p).s(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, AbstractC3169i5.g(c0814p).o, c0814p, 0, 0, 65528);
                c0814p = c0814p;
                c0814p.p(false);
            } else if (gradedAnswer instanceof com.quizlet.features.practicetest.results.data.b) {
                c0814p.X(-598695123);
                androidx.compose.ui.q qVarA2 = i0.a(nVar, 1.0f, true);
                com.quizlet.themes.m.g.w();
                z2 = true;
                a(AbstractC3106b5.d(c0814p, R.string.practice_test_results_unsupported_question), (com.quizlet.features.practicetest.results.data.b) gradedAnswer, null, null, AbstractC0382e.y(qVarA2, com.quizlet.ui.resources.designsystem.generated.j.f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 14), c0814p, 3456);
                c0814p.p(false);
            } else {
                c0814p.X(-598250211);
                androidx.compose.ui.q qVarA3 = i0.a(nVar, 1.0f, true);
                com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
                mVar.w();
                int i5 = i3 >> 9;
                a(question, gradedAnswer, str, str2, AbstractC0382e.y(qVarA3, com.quizlet.ui.resources.designsystem.generated.j.f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 14), c0814p, (i5 & 896) | (i3 & 14) | ((i3 >> 3) & ContentType.LONG_FORM_ON_DEMAND) | (i5 & 7168));
                mVar.g();
                androidx.compose.ui.q qVarK = K0.k(nVar, com.quizlet.ui.resources.designsystem.generated.h.h);
                ((com.quizlet.themes.d) c0814p.j(com.quizlet.themes.e.a)).a.getClass();
                androidx.compose.ui.graphics.painter.b bVarX = com.quizlet.ui.resources.icons.d.x(c0814p);
                C4076a c4076a = C4076a.f;
                com.quizlet.assembly.compose.buttons.B b = com.quizlet.assembly.compose.buttons.B.a;
                String strD = AbstractC3106b5.d(c0814p, R.string.practice_test_content_description_report_question);
                long j = C0861v.f;
                z2 = true;
                V4.a(bVarX, strD, new C4078c(j, AbstractC3169i5.f(c0814p).S0, j, AbstractC3169i5.f(c0814p).b.b(), AbstractC3169i5.f(c0814p).r(), 32), qVarK, function0, false, c4076a, b, null, c0814p, 12582912 | (57344 & i5), 800);
                c0814p = c0814p;
                c0814p.p(false);
            }
            c0814p.p(z2);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.practicetest.results.composables.h(question, i, gradedAnswer, z, qVar, str, str2, function0, i2);
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:64:0x00cb, code lost:
    
        if (r7 == 16) goto L69;
     */
    /* JADX WARN: Code restructure failed: missing block: B:65:0x00cd, code lost:
    
        if (r8 != (-1)) goto L68;
     */
    /* JADX WARN: Code restructure failed: missing block: B:68:0x00d1, code lost:
    
        r0 = r7 - r8;
        java.lang.System.arraycopy(r3, r8, r3, 16 - r0, r0);
        java.util.Arrays.fill(r3, r8, (16 - r7) + r8, (byte) 0);
     */
    /* JADX WARN: Code restructure failed: missing block: B:70:0x00e1, code lost:
    
        return java.net.InetAddress.getByAddress(r3);
     */
    /* JADX WARN: Code restructure failed: missing block: B:90:?, code lost:
    
        return null;
     */
    /* JADX WARN: Removed duplicated region for block: B:55:0x00a2  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.net.InetAddress c(int r17, int r18, java.lang.String r19) {
        /*
            Method dump skipped, instructions count: 226
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.transition.C1405h.c(int, int, java.lang.String):java.net.InetAddress");
    }

    public static final String d(String str) {
        Intrinsics.checkNotNullParameter(str, "<this>");
        int i = 0;
        int i2 = -1;
        if (!StringsKt.G(str, ":", false)) {
            try {
                String ascii = IDN.toASCII(str);
                Intrinsics.checkNotNullExpressionValue(ascii, "toASCII(host)");
                Locale US = Locale.US;
                Intrinsics.checkNotNullExpressionValue(US, "US");
                String lowerCase = ascii.toLowerCase(US);
                Intrinsics.checkNotNullExpressionValue(lowerCase, "this as java.lang.String).toLowerCase(locale)");
                if (lowerCase.length() == 0) {
                    return null;
                }
                int length = lowerCase.length();
                for (int i3 = 0; i3 < length; i3++) {
                    char cCharAt = lowerCase.charAt(i3);
                    if (Intrinsics.g(cCharAt, 31) <= 0 || Intrinsics.g(cCharAt, 127) >= 0 || StringsKt.L(" #%/:?@[\\]", cCharAt, 0, false, 6) != -1) {
                        return null;
                    }
                }
                return lowerCase;
            } catch (IllegalArgumentException unused) {
                return null;
            }
        }
        InetAddress inetAddressC = (kotlin.text.D.r(str, "[", false) && kotlin.text.D.k(str, "]", false)) ? c(1, str.length() - 1, str) : c(0, str.length(), str);
        if (inetAddressC == null) {
            return null;
        }
        byte[] address = inetAddressC.getAddress();
        if (address.length != 16) {
            if (address.length == 4) {
                return inetAddressC.getHostAddress();
            }
            throw new AssertionError(androidx.compose.ui.node.B.h("Invalid IPv6 address: '", str, '\''));
        }
        Intrinsics.checkNotNullExpressionValue(address, "address");
        int i4 = 0;
        int i5 = 0;
        while (i4 < address.length) {
            int i6 = i4;
            while (i6 < 16 && address[i6] == 0 && address[i6 + 1] == 0) {
                i6 += 2;
            }
            int i7 = i6 - i4;
            if (i7 > i5 && i7 >= 4) {
                i2 = i4;
                i5 = i7;
            }
            i4 = i6 + 2;
        }
        C5091h c5091h = new C5091h();
        while (i < address.length) {
            if (i == i2) {
                c5091h.p0(58);
                i += i5;
                if (i == 16) {
                    c5091h.p0(58);
                }
            } else {
                if (i > 0) {
                    c5091h.p0(58);
                }
                byte b = address[i];
                byte[] bArr = okhttp3.internal.b.a;
                c5091h.r0(((b & 255) << 8) | (address[i + 1] & 255));
                i += 2;
            }
        }
        return c5091h.U();
    }
}

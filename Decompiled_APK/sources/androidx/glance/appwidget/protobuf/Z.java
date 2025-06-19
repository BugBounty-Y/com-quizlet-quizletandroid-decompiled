package androidx.glance.appwidget.protobuf;

import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.C0386g;
import androidx.compose.foundation.layout.K0;
import androidx.compose.material3.Q4;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import com.amazon.device.ads.DtbConstants;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_barcode.K5;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3409x1;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3515q;
import com.quizlet.data.model.m2;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Pair;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class Z {
    public final /* synthetic */ int a;

    public /* synthetic */ Z(int i) {
        this.a = i;
    }

    public static final void a(m2 source, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        Pair pair;
        Intrinsics.checkNotNullParameter(source, "source");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1073898285);
        if ((((c0814p.f(source) ? 4 : 2) | i | (c0814p.f(qVar) ? 32 : 16)) & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            Intrinsics.checkNotNullParameter(source, "source");
            int iOrdinal = source.ordinal();
            if (iOrdinal == 0) {
                pair = new Pair(Integer.valueOf(R.raw.lottie_generating_notes), Integer.valueOf(R.string.upload_notes_creating_magic_notes_text));
            } else {
                if (iOrdinal != 1) {
                    if (iOrdinal == 2) {
                        throw new kotlin.n(null, 1, null);
                    }
                    throw new NoWhenBranchMatchedException();
                }
                pair = new Pair(Integer.valueOf(R.raw.lottie_generating_flashcards), Integer.valueOf(R.string.upload_notes_creating_flashcards_text));
            }
            int iIntValue = ((Number) pair.a).intValue();
            int iIntValue2 = ((Number) pair.b).intValue();
            androidx.compose.ui.g gVar = androidx.compose.ui.b.n;
            C0386g c0386g = AbstractC0398m.e;
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.q();
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(AbstractC0382e.u(qVar, com.quizlet.ui.resources.designsystem.generated.j.i).g(K0.c), "creatingMagicNotes");
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(c0386g, gVar, c0814p, 54);
            int i2 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarG);
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i2))) {
                android.support.v4.media.session.a.z(i2, c0814p, i2, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            kotlinx.collections.immutable.e eVarH = AbstractC3409x1.h(AbstractC3106b5.d(c0814p, iIntValue2));
            androidx.compose.runtime.B b = com.quizlet.themes.g.a;
            long jF = ((com.quizlet.themes.b) c0814p.j(b)).F();
            ((com.quizlet.themes.b) c0814p.j(b)).c.getClass();
            com.quizlet.ui.compose.animations.a aVarC = K5.c(eVarH, jF, com.quizlet.ui.resources.designsystem.generated.d.G, c0814p);
            com.airbnb.lottie.h hVar = (com.airbnb.lottie.h) com.google.android.gms.internal.mlkit_vision_common.r.d(new com.airbnb.lottie.compose.o(iIntValue), c0814p).getValue();
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            AbstractC3515q.a(hVar, androidx.compose.ui.platform.N.G(K0.k(nVar, com.quizlet.themes.m.C0), source == m2.a ? "studyGuidesImage" : "flashcardsImage"), SubsamplingScaleImageView.TILE_SIZE_AUTO, null, null, c0814p, 1572864, 0, 4194236);
            androidx.compose.runtime.B b2 = com.quizlet.themes.w.a;
            androidx.compose.ui.text.L lA = androidx.compose.ui.text.L.a(((com.quizlet.themes.f) c0814p.j(b2)).d, aVarC.b);
            mVar.p();
            Q4.b(aVarC.a, K0.d(AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.j, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), com.quizlet.themes.m.I), 0L, 0L, null, 0L, new androidx.compose.ui.text.style.i(3), 0L, 0, false, 0, 0, null, lA, c0814p, 0, 0, 65020);
            String strD = AbstractC3106b5.d(c0814p, R.string.upload_notes_creating_magic_notes);
            androidx.compose.ui.text.L l = ((com.quizlet.themes.f) c0814p.j(b2)).j;
            long jF2 = ((com.quizlet.themes.b) c0814p.j(b)).b.f();
            mVar.s();
            Q4.b(strD, AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.h, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), jF2, 0L, null, 0L, new androidx.compose.ui.text.style.i(3), 0L, 0, false, 0, 0, null, l, c0814p, 0, 0, 65016);
            c0814p = c0814p;
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.notes.upload.composables.common.c(source, qVar, i, 0);
        }
    }

    public static final kotlin.q b(Throwable exception) {
        Intrinsics.checkNotNullParameter(exception, "exception");
        return new kotlin.q(exception);
    }

    public static final void e(Object obj) {
        if (obj instanceof kotlin.q) {
            throw ((kotlin.q) obj).a;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:20:0x004a  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.String c(int r11, byte[] r12, int r13) {
        /*
            Method dump skipped, instructions count: 352
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.glance.appwidget.protobuf.Z.c(int, byte[], int):java.lang.String");
    }

    public final int d(String str, byte[] bArr, int i, int i2) {
        int i3;
        int i4;
        char cCharAt;
        long j;
        char c;
        long j2;
        long j3;
        char c2;
        int i5;
        char cCharAt2;
        switch (this.a) {
            case 0:
                int length = str.length();
                int i6 = i2 + i;
                int i7 = 0;
                while (i7 < length && (i4 = i7 + i) < i6 && (cCharAt = str.charAt(i7)) < 128) {
                    bArr[i4] = (byte) cCharAt;
                    i7++;
                }
                if (i7 == length) {
                    return i + length;
                }
                int i8 = i + i7;
                while (i7 < length) {
                    char cCharAt3 = str.charAt(i7);
                    if (cCharAt3 < 128 && i8 < i6) {
                        bArr[i8] = (byte) cCharAt3;
                        i8++;
                    } else if (cCharAt3 < 2048 && i8 <= i6 - 2) {
                        int i9 = i8 + 1;
                        bArr[i8] = (byte) ((cCharAt3 >>> 6) | 960);
                        i8 += 2;
                        bArr[i9] = (byte) ((cCharAt3 & '?') | 128);
                    } else {
                        if ((cCharAt3 >= 55296 && 57343 >= cCharAt3) || i8 > i6 - 3) {
                            if (i8 > i6 - 4) {
                                if (55296 <= cCharAt3 && cCharAt3 <= 57343 && ((i3 = i7 + 1) == str.length() || !Character.isSurrogatePair(cCharAt3, str.charAt(i3)))) {
                                    throw new a0(i7, length);
                                }
                                throw new ArrayIndexOutOfBoundsException("Failed writing " + cCharAt3 + " at index " + i8);
                            }
                            int i10 = i7 + 1;
                            if (i10 != str.length()) {
                                char cCharAt4 = str.charAt(i10);
                                if (Character.isSurrogatePair(cCharAt3, cCharAt4)) {
                                    int codePoint = Character.toCodePoint(cCharAt3, cCharAt4);
                                    bArr[i8] = (byte) ((codePoint >>> 18) | 240);
                                    bArr[i8 + 1] = (byte) (((codePoint >>> 12) & 63) | 128);
                                    int i11 = i8 + 3;
                                    bArr[i8 + 2] = (byte) (((codePoint >>> 6) & 63) | 128);
                                    i8 += 4;
                                    bArr[i11] = (byte) ((codePoint & 63) | 128);
                                    i7 = i10;
                                } else {
                                    i7 = i10;
                                }
                            }
                            throw new a0(i7 - 1, length);
                        }
                        bArr[i8] = (byte) ((cCharAt3 >>> '\f') | DtbConstants.DEFAULT_PLAYER_HEIGHT);
                        int i12 = i8 + 2;
                        bArr[i8 + 1] = (byte) (((cCharAt3 >>> 6) & 63) | 128);
                        i8 += 3;
                        bArr[i12] = (byte) ((cCharAt3 & '?') | 128);
                    }
                    i7++;
                }
                return i8;
            default:
                long j4 = i;
                long j5 = i2 + j4;
                int length2 = str.length();
                if (length2 > i2 || bArr.length - i2 < i) {
                    throw new ArrayIndexOutOfBoundsException("Failed writing " + str.charAt(length2 - 1) + " at index " + (i + i2));
                }
                int i13 = 0;
                while (true) {
                    j = 1;
                    c = 128;
                    if (i13 < length2 && (cCharAt2 = str.charAt(i13)) < 128) {
                        Y.j(bArr, (byte) cCharAt2, j4);
                        i13++;
                        j4 = 1 + j4;
                    }
                }
                if (i13 == length2) {
                    return (int) j4;
                }
                while (i13 < length2) {
                    char cCharAt5 = str.charAt(i13);
                    if (cCharAt5 < c && j4 < j5) {
                        Y.j(bArr, (byte) cCharAt5, j4);
                        c2 = c;
                        j2 = j;
                        j3 = j4 + j;
                    } else if (cCharAt5 >= 2048 || j4 > j5 - 2) {
                        j2 = j;
                        if ((cCharAt5 >= 55296 && 57343 >= cCharAt5) || j4 > j5 - 3) {
                            long j6 = j4;
                            if (j6 > j5 - 4) {
                                if (55296 <= cCharAt5 && cCharAt5 <= 57343 && ((i5 = i13 + 1) == length2 || !Character.isSurrogatePair(cCharAt5, str.charAt(i5)))) {
                                    throw new a0(i13, length2);
                                }
                                throw new ArrayIndexOutOfBoundsException("Failed writing " + cCharAt5 + " at index " + j6);
                            }
                            int i14 = i13 + 1;
                            if (i14 != length2) {
                                char cCharAt6 = str.charAt(i14);
                                if (Character.isSurrogatePair(cCharAt5, cCharAt6)) {
                                    int codePoint2 = Character.toCodePoint(cCharAt5, cCharAt6);
                                    Y.j(bArr, (byte) ((codePoint2 >>> 18) | 240), j6);
                                    c2 = 128;
                                    Y.j(bArr, (byte) (((codePoint2 >>> 12) & 63) | 128), j6 + j2);
                                    Y.j(bArr, (byte) (((codePoint2 >>> 6) & 63) | 128), j6 + 2);
                                    Y.j(bArr, (byte) ((codePoint2 & 63) | 128), j6 + 3);
                                    j3 = j6 + 4;
                                    i13 = i14;
                                } else {
                                    i13 = i14;
                                }
                            }
                            throw new a0(i13 - 1, length2);
                        }
                        Y.j(bArr, (byte) ((cCharAt5 >>> '\f') | DtbConstants.DEFAULT_PLAYER_HEIGHT), j4);
                        long j7 = j4;
                        Y.j(bArr, (byte) (((cCharAt5 >>> 6) & 63) | 128), j4 + j2);
                        j3 = j7 + 3;
                        Y.j(bArr, (byte) ((cCharAt5 & '?') | 128), j7 + 2);
                        c2 = 128;
                    } else {
                        j2 = j;
                        Y.j(bArr, (byte) ((cCharAt5 >>> 6) | 960), j4);
                        Y.j(bArr, (byte) ((cCharAt5 & '?') | c), j4 + j2);
                        j3 = j4 + 2;
                        c2 = c;
                    }
                    i13++;
                    c = c2;
                    j4 = j3;
                    j = j2;
                }
                return (int) j4;
        }
    }
}

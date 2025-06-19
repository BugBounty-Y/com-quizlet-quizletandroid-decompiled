package com.google.android.gms.internal.mlkit_vision_document_scanner;

import android.graphics.ColorFilter;
import android.graphics.PorterDuffColorFilter;
import android.os.Build;
import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.graphics.C0853m;
import androidx.compose.ui.graphics.C0854n;
import androidx.compose.ui.graphics.I;
import androidx.compose.ui.q;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3587b6;
import com.quizlet.data.model.AbstractC4165s1;
import com.quizlet.data.model.C4157p1;
import com.quizlet.data.model.C4160q1;
import com.quizlet.data.model.C4162r1;
import com.quizlet.data.model.Course;
import com.quizlet.data.model.School;
import com.quizlet.data.model.StudySet;
import com.quizlet.data.model.StudySetWithCreator;
import com.quizlet.data.model.User;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.quizletandroid.ui.startpage.nav2.model.C4706b;
import com.quizlet.quizletandroid.ui.startpage.nav2.model.C4709e;
import com.quizlet.quizletandroid.ui.startpage.nav2.model.C4723t;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.List;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.b6, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3587b6 {
    /* JADX WARN: Removed duplicated region for block: B:27:0x0052  */
    /* JADX WARN: Removed duplicated region for block: B:30:0x005d  */
    /* JADX WARN: Removed duplicated region for block: B:34:0x0066  */
    /* JADX WARN: Removed duplicated region for block: B:37:0x0071  */
    /* JADX WARN: Removed duplicated region for block: B:41:0x007a  */
    /* JADX WARN: Removed duplicated region for block: B:42:0x0080  */
    /* JADX WARN: Removed duplicated region for block: B:49:0x0092  */
    /* JADX WARN: Removed duplicated region for block: B:50:0x0098  */
    /* JADX WARN: Removed duplicated region for block: B:57:0x00af  */
    /* JADX WARN: Removed duplicated region for block: B:62:0x00c1  */
    /* JADX WARN: Removed duplicated region for block: B:76:0x00e7  */
    /* JADX WARN: Removed duplicated region for block: B:77:0x00e9  */
    /* JADX WARN: Removed duplicated region for block: B:80:0x00f0  */
    /* JADX WARN: Removed duplicated region for block: B:83:0x0104  */
    /* JADX WARN: Removed duplicated region for block: B:86:0x0114  */
    /* JADX WARN: Removed duplicated region for block: B:89:0x011b  */
    /* JADX WARN: Removed duplicated region for block: B:91:0x011e  */
    /* JADX WARN: Removed duplicated region for block: B:95:0x0160  */
    /* JADX WARN: Removed duplicated region for block: B:97:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void a(final java.lang.String r16, androidx.compose.ui.q r17, long r18, long r20, long r22, androidx.compose.ui.graphics.painter.b r24, androidx.compose.ui.graphics.painter.b r25, androidx.compose.runtime.InterfaceC0806l r26, final int r27, final int r28) {
        /*
            Method dump skipped, instructions count: 366
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3587b6.a(java.lang.String, androidx.compose.ui.q, long, long, long, androidx.compose.ui.graphics.painter.b, androidx.compose.ui.graphics.painter.b, androidx.compose.runtime.l, int, int):void");
    }

    public static final void b(androidx.compose.ui.q qVar, long j, long j2, androidx.compose.runtime.internal.d dVar, InterfaceC0806l interfaceC0806l, int i, int i2) {
        androidx.compose.ui.q qVar2;
        int i3;
        long jF;
        long j3;
        androidx.compose.ui.q qVar3;
        long j4;
        long j5;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(316875720);
        int i4 = i2 & 1;
        if (i4 != 0) {
            i3 = i | 6;
            qVar2 = qVar;
        } else if ((i & 6) == 0) {
            qVar2 = qVar;
            i3 = (c0814p.f(qVar2) ? 4 : 2) | i;
        } else {
            qVar2 = qVar;
            i3 = i;
        }
        if ((i & 48) == 0) {
            if ((i2 & 2) == 0) {
                jF = j;
                int i5 = c0814p.e(jF) ? 32 : 16;
                i3 |= i5;
            } else {
                jF = j;
            }
            i3 |= i5;
        } else {
            jF = j;
        }
        if ((i & 384) == 0) {
            if ((i2 & 4) == 0) {
                j3 = j2;
                int i6 = c0814p.e(j3) ? 256 : 128;
                i3 |= i6;
            } else {
                j3 = j2;
            }
            i3 |= i6;
        } else {
            j3 = j2;
        }
        if ((i & 3072) == 0) {
            i3 |= c0814p.h(dVar) ? 2048 : 1024;
        }
        if ((i3 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
            j5 = jF;
            j4 = j3;
        } else {
            c0814p.S();
            if ((i & 1) == 0 || c0814p.w()) {
                androidx.compose.ui.q qVar4 = i4 != 0 ? androidx.compose.ui.n.b : qVar2;
                if ((i2 & 2) != 0) {
                    jF = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.f();
                    i3 &= -113;
                }
                if ((i2 & 4) != 0) {
                    j3 = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).z;
                    i3 &= -897;
                }
                qVar3 = qVar4;
            } else {
                c0814p.Q();
                if ((i2 & 2) != 0) {
                    i3 &= -113;
                }
                if ((i2 & 4) != 0) {
                    i3 &= -897;
                }
                qVar3 = qVar2;
            }
            long j6 = jF;
            long j7 = j3;
            c0814p.q();
            androidx.compose.material3.H.a(qVar3, j7, j6, dVar, c0814p, (i3 & 14) | ((i3 >> 3) & ContentType.LONG_FORM_ON_DEMAND) | ((i3 << 3) & 896) | (i3 & 7168));
            qVar2 = qVar3;
            j4 = j7;
            j5 = j6;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.pills.d(qVar2, j5, j4, dVar, i, i2, 0);
        }
    }

    public static final void c(final String text, final androidx.compose.ui.graphics.I backgroundColor, final androidx.compose.ui.q qVar, final long j, InterfaceC0806l interfaceC0806l, final int i) {
        Intrinsics.checkNotNullParameter(text, "text");
        Intrinsics.checkNotNullParameter(backgroundColor, "backgroundColor");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1459147210);
        if ((((c0814p.f(text) ? 4 : 2) | i | (c0814p.f(backgroundColor) ? 32 : 16) | (c0814p.f(qVar) ? 256 : 128) | (c0814p.e(j) ? 2048 : 1024) | 221184) & 74899) == 74898 && c0814p.x()) {
            c0814p.Q();
        } else {
            c0814p.S();
            if ((i & 1) != 0 && !c0814p.w()) {
                c0814p.Q();
            }
            c0814p.q();
            androidx.compose.ui.q qVarE = AbstractC0460p.e(androidx.compose.ui.draw.g.c(qVar, com.quizlet.assembly.compose.pills.a.a), backgroundColor, null, 6);
            androidx.compose.runtime.internal.d dVar = com.quizlet.assembly.compose.pills.k.a;
            androidx.compose.material3.H.b(qVarE, androidx.compose.runtime.internal.e.e(333194640, new com.quizlet.assembly.compose.pills.i(text, j, 0), c0814p), c0814p, 390);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new Function2(text, backgroundColor, qVar, j, i) { // from class: com.quizlet.assembly.compose.pills.c
                public final /* synthetic */ String a;
                public final /* synthetic */ I b;
                public final /* synthetic */ q c;
                public final /* synthetic */ long d;

                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(Object obj, Object obj2) {
                    ((Integer) obj2).getClass();
                    int iH = C0776c.H(1);
                    I i2 = this.b;
                    q qVar2 = this.c;
                    long j2 = this.d;
                    AbstractC3587b6.c(this.a, i2, qVar2, j2, (InterfaceC0806l) obj, iH);
                    return Unit.a;
                }
            };
        }
    }

    public static final void d(androidx.compose.ui.graphics.painter.b icon, androidx.compose.ui.q qVar, String str, long j, long j2, InterfaceC0806l interfaceC0806l, int i, int i2) {
        int i3;
        String str2;
        androidx.compose.ui.q qVar2;
        String str3;
        Intrinsics.checkNotNullParameter(icon, "icon");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1321477232);
        if ((i & 6) == 0) {
            i3 = (c0814p.h(icon) ? 4 : 2) | i;
        } else {
            i3 = i;
        }
        int i4 = i2 & 2;
        if (i4 != 0) {
            i3 |= 48;
        } else if ((i & 48) == 0) {
            i3 |= c0814p.f(qVar) ? 32 : 16;
        }
        int i5 = i2 & 4;
        if (i5 != 0) {
            i3 |= 384;
        } else if ((i & 384) == 0) {
            i3 |= c0814p.f(str) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i3 |= c0814p.e(j) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i3 |= c0814p.e(j2) ? 16384 : 8192;
        }
        if ((i3 & 9363) == 9362 && c0814p.x()) {
            c0814p.Q();
            qVar2 = qVar;
            str3 = str;
        } else {
            c0814p.S();
            if ((i & 1) == 0 || c0814p.w()) {
                if (i4 != 0) {
                    qVar = androidx.compose.ui.n.b;
                }
                str2 = i5 != 0 ? null : str;
            } else {
                c0814p.Q();
                str2 = str;
            }
            c0814p.q();
            androidx.compose.runtime.internal.d dVarE = androidx.compose.runtime.internal.e.e(-176555769, new com.quizlet.assembly.compose.pills.h(icon, str2, j), c0814p);
            int i6 = ((i3 >> 3) & 14) | 3072;
            int i7 = i3 >> 6;
            int i8 = (i7 & 896) | i6 | (i7 & ContentType.LONG_FORM_ON_DEMAND);
            androidx.compose.ui.q qVar3 = qVar;
            b(qVar3, j, j2, dVarE, c0814p, i8, 0);
            qVar2 = qVar3;
            str3 = str2;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.pills.f(icon, qVar2, str3, j, j2, i, i2);
        }
    }

    public static final void e(final androidx.compose.foundation.layout.H0 h0, final String str, final long j, long j2, final androidx.compose.ui.graphics.painter.b bVar, final androidx.compose.ui.graphics.painter.b bVar2, InterfaceC0806l interfaceC0806l, final int i, final int i2) {
        int i3;
        long j3;
        androidx.compose.ui.n nVar;
        C0814p c0814p;
        long j4;
        int i4;
        C0854n c0854n;
        int i5;
        long j5;
        int i6;
        ColorFilter porterDuffColorFilter;
        final long j6;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(288691799);
        if ((i & 48) == 0) {
            i3 = (c0814p2.f(str) ? 32 : 16) | i;
        } else {
            i3 = i;
        }
        if ((i & 384) == 0) {
            i3 |= c0814p2.e(j) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            if ((i2 & 4) == 0) {
                j3 = j2;
                int i7 = c0814p2.e(j3) ? 2048 : 1024;
                i3 |= i7;
            } else {
                j3 = j2;
            }
            i3 |= i7;
        } else {
            j3 = j2;
        }
        if ((i & 24576) == 0) {
            i3 |= c0814p2.h(bVar) ? 16384 : 8192;
        }
        if ((196608 & i) == 0) {
            i3 |= c0814p2.h(bVar2) ? 131072 : 65536;
        }
        if ((74897 & i3) == 74896 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
            j6 = j3;
        } else {
            c0814p2.S();
            if ((i & 1) != 0 && !c0814p2.w()) {
                c0814p2.Q();
                if ((i2 & 4) != 0) {
                    i3 &= -7169;
                }
            } else if ((i2 & 4) != 0) {
                i3 &= -7169;
                j3 = j;
            }
            long j7 = j3;
            int i8 = i3;
            c0814p2.q();
            c0814p2.X(-1494285828);
            C0854n c0854n2 = C0854n.a;
            androidx.compose.ui.n nVar2 = androidx.compose.ui.n.b;
            if (bVar == null) {
                c0814p = c0814p2;
                j4 = j7;
                i4 = i8;
                c0854n = c0854n2;
                i5 = 29;
                nVar = nVar2;
            } else {
                C0853m c0853m = new C0853m(j7, 5, Build.VERSION.SDK_INT >= 29 ? c0854n2.a(j7, 5) : new PorterDuffColorFilter(androidx.compose.ui.graphics.F.A(j7), androidx.compose.ui.graphics.F.E(5)));
                com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
                mVar.w();
                androidx.compose.ui.q qVarY = AbstractC0382e.y(nVar2, com.quizlet.ui.resources.designsystem.generated.j.f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 14);
                nVar = nVar2;
                mVar.i();
                c0814p = c0814p2;
                j4 = j7;
                i4 = i8;
                c0854n = c0854n2;
                i5 = 29;
                AbstractC0460p.c(bVar, null, androidx.compose.ui.platform.N.G(androidx.compose.foundation.layout.K0.k(qVarY, com.quizlet.ui.resources.designsystem.generated.h.f), "startImage"), null, null, DefinitionKt.NO_Float_VALUE, c0853m, c0814p, 48, 56);
                Unit unit = Unit.a;
            }
            c0814p.p(false);
            androidx.compose.ui.text.L l = ((com.quizlet.themes.f) c0814p.j(com.quizlet.themes.w.a)).l;
            androidx.compose.ui.q qVarW = AbstractC0382e.w(nVar, DefinitionKt.NO_Float_VALUE, 2, 1);
            com.quizlet.themes.m mVar2 = com.quizlet.themes.m.g;
            mVar2.u();
            androidx.compose.material3.Q4.b(str, AbstractC0382e.w(qVarW, com.quizlet.ui.resources.designsystem.generated.j.g, DefinitionKt.NO_Float_VALUE, 2), j, 0L, null, 0L, null, 0L, 0, false, 0, 0, null, l, c0814p, ((i4 >> 3) & 14) | (i4 & 896), 0, 65528);
            if (bVar2 == null) {
                j5 = j4;
            } else {
                if (Build.VERSION.SDK_INT >= i5) {
                    j5 = j4;
                    i6 = 5;
                    porterDuffColorFilter = c0854n.a(j5, 5);
                } else {
                    j5 = j4;
                    i6 = 5;
                    porterDuffColorFilter = new PorterDuffColorFilter(androidx.compose.ui.graphics.F.A(j5), androidx.compose.ui.graphics.F.E(5));
                }
                C0853m c0853m2 = new C0853m(j5, i6, porterDuffColorFilter);
                mVar2.w();
                androidx.compose.ui.q qVarY2 = AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.f, DefinitionKt.NO_Float_VALUE, 11);
                mVar2.i();
                AbstractC0460p.c(bVar2, null, androidx.compose.ui.platform.N.G(androidx.compose.foundation.layout.K0.k(qVarY2, com.quizlet.ui.resources.designsystem.generated.h.f), "endImage"), null, null, DefinitionKt.NO_Float_VALUE, c0853m2, c0814p, 48, 56);
            }
            j6 = j5;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new Function2() { // from class: com.quizlet.assembly.compose.pills.e
                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(Object obj, Object obj2) {
                    ((Integer) obj2).getClass();
                    int iH = C0776c.H(i | 1);
                    androidx.compose.ui.graphics.painter.b bVar3 = bVar2;
                    AbstractC3587b6.e(h0, str, j, j6, bVar, bVar3, (InterfaceC0806l) obj, iH, i2);
                    return Unit.a;
                }
            };
        }
    }

    public static final C4723t f(AbstractC4165s1 abstractC4165s1) {
        Intrinsics.checkNotNullParameter(abstractC4165s1, "<this>");
        List<StudySetWithCreator> listA = abstractC4165s1.a();
        ArrayList arrayList = new ArrayList(kotlin.collections.C.q(listA, 10));
        for (StudySetWithCreator studySetWithCreator : listA) {
            DBStudySet dBStudySetB = com.quizlet.local.ormlite.models.set.a.b(studySetWithCreator.a);
            User user = studySetWithCreator.b;
            if (user != null) {
                dBStudySetB.setCreator(assistantMode.utils.studiableMetadata.b.P(user));
            }
            arrayList.add(dBStudySetB);
        }
        Intrinsics.checkNotNullParameter(abstractC4165s1, "<this>");
        AbstractC3603d6 n = null;
        if (abstractC4165s1 instanceof C4160q1) {
            C4160q1 c4160q1 = (C4160q1) abstractC4165s1;
            User user2 = c4160q1.b;
            if (user2 != null) {
                n = new com.quizlet.quizletandroid.ui.startpage.nav2.model.T(user2.b);
            } else {
                StudySet studySet = c4160q1.c;
                if (studySet != null) {
                    n = new com.quizlet.quizletandroid.ui.startpage.nav2.model.Q(studySet.h);
                }
            }
        } else if (abstractC4165s1 instanceof C4162r1) {
            C4162r1 c4162r1 = (C4162r1) abstractC4165s1;
            School school = c4162r1.b;
            Course course = c4162r1.c;
            if (course != null) {
                n = new C4709e(course.e, school != null);
            } else if (school != null) {
                n = new com.quizlet.quizletandroid.ui.startpage.nav2.model.N(school.i);
            }
        } else {
            if (!(abstractC4165s1 instanceof C4157p1)) {
                throw new NoWhenBranchMatchedException();
            }
            n = C4706b.a;
        }
        return new C4723t(arrayList, n);
    }
}

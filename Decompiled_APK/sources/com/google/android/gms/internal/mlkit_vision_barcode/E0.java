package com.google.android.gms.internal.mlkit_vision_barcode;

import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.material.AbstractC0578v;
import androidx.compose.material.C0576t;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.graphics.C0861v;
import com.comscore.streaming.ContentType;
import com.quizlet.data.model.C4113b2;
import com.quizlet.data.model.C4133h1;
import com.quizlet.data.model.C4136i1;
import com.quizlet.data.model.C4154o1;
import com.quizlet.data.model.School;
import com.quizlet.data.model.StudySet;
import com.quizlet.data.model.Textbook;
import com.quizlet.data.model.User;
import com.quizlet.quizletandroid.R;
import java.util.Locale;
import java.util.NoSuchElementException;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class E0 {
    public static final /* synthetic */ int a = 0;

    public static final void a(androidx.compose.material.navigation.i iVar, androidx.compose.ui.n nVar, boolean z, androidx.compose.foundation.shape.d dVar, float f, long j, long j2, long j3, androidx.compose.runtime.internal.d dVar2, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        androidx.compose.ui.n nVar2;
        boolean z2;
        float f2;
        long j4;
        long j5;
        long jA;
        int i3;
        float f3;
        boolean z3;
        long jB;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1852297955);
        if ((i & 6) == 0) {
            i2 = ((i & 8) == 0 ? c0814p.f(iVar) : c0814p.h(iVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            nVar2 = nVar;
            i2 |= c0814p.f(nVar2) ? 32 : 16;
        } else {
            nVar2 = nVar;
        }
        int i4 = i2 | 384;
        if ((i & 3072) == 0) {
            i4 |= c0814p.f(dVar) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i4 |= 8192;
        }
        if ((196608 & i) == 0) {
            i4 |= c0814p.e(j) ? 131072 : 65536;
        }
        if ((1572864 & i) == 0) {
            i4 |= 524288;
        }
        if ((12582912 & i) == 0) {
            i4 |= 4194304;
        }
        if ((100663296 & i) == 0) {
            i4 |= c0814p.h(dVar2) ? 67108864 : 33554432;
        }
        if (c0814p.N(i4 & 1, (38347923 & i4) != 38347922)) {
            c0814p.S();
            if ((i & 1) == 0 || c0814p.w()) {
                float f4 = androidx.compose.material.H.a;
                jA = AbstractC0578v.a(j, c0814p);
                i3 = i4 & (-33087489);
                f3 = f4;
                z3 = true;
                jB = C0861v.b(((C0861v) ((androidx.compose.runtime.L0) ((C0576t) c0814p.j(AbstractC0578v.a)).k).getValue()).a, 0.32f);
            } else {
                c0814p.Q();
                i3 = i4 & (-33087489);
                z3 = z;
                f3 = f;
                jA = j2;
                jB = j3;
            }
            c0814p.q();
            androidx.compose.material.e0 e0Var = iVar.c;
            int i5 = (i3 & ContentType.LONG_FORM_ON_DEMAND) | com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH;
            int i6 = i3 << 3;
            androidx.compose.material.Z.a(iVar.e, nVar2, e0Var, z3, dVar, f3, j, jA, jB, dVar2, c0814p, i5 | (i6 & 7168) | (57344 & i6) | (3670016 & i6) | (i6 & 1879048192));
            z2 = z3;
            f2 = f3;
            j4 = jA;
            j5 = jB;
        } else {
            c0814p.Q();
            z2 = z;
            f2 = f;
            j4 = j2;
            j5 = j3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.compose.material.navigation.a(iVar, nVar, z2, dVar, f2, j, j4, j5, dVar2, i);
        }
    }

    public static final com.quizlet.ui.models.content.carditem.a b(C4136i1 c4136i1) {
        int i;
        int i2;
        String str;
        String str2;
        Intrinsics.checkNotNullParameter(c4136i1, "<this>");
        C4133h1 c4133h1 = c4136i1.a;
        long j = c4133h1.a;
        String str3 = c4133h1.b;
        int i3 = (int) c4133h1.k;
        int i4 = (int) c4133h1.j;
        String strL = null;
        School school = c4136i1.b;
        String str4 = school != null ? school.i : null;
        if (str4 == null) {
            str4 = "";
        }
        if (school != null) {
            Intrinsics.checkNotNullParameter(school, "<this>");
            String str5 = school.b;
            if (str5 == null || str5.length() == 0) {
                strL = "";
            } else {
                String strD = AbstractC0147y.d("", str5);
                String str6 = school.j;
                strL = (str6 == null || str6.length() == 0) ? strD : android.support.v4.media.session.a.l(strD, ", ", str6);
            }
        }
        if (strL == null) {
            i = i4;
            i2 = i3;
            str2 = str4;
            str = "";
        } else {
            i = i4;
            i2 = i3;
            String str7 = str4;
            str = strL;
            str2 = str7;
        }
        return new com.quizlet.ui.models.content.carditem.a(j, str3, i2, i, str2, str);
    }

    public static final com.quizlet.ui.models.content.carditem.e c(com.quizlet.data.model.Z z, boolean z2) {
        Intrinsics.checkNotNullParameter(z, "<this>");
        C4154o1 c4154o1 = (C4154o1) z;
        String strValueOf = String.valueOf(c4154o1.a);
        com.quizlet.generated.enums.D d = (com.quizlet.generated.enums.D) CollectionsKt.firstOrNull(c4154o1.h);
        return new com.quizlet.ui.models.content.carditem.e(strValueOf, c4154o1.b, "", d != null ? Integer.valueOf(G6.d(d)) : null, z2);
    }

    public static final com.quizlet.ui.models.content.carditem.f d(C4113b2 c4113b2) {
        com.quizlet.ui.models.search.e eVar;
        com.quizlet.ui.models.search.d dVar;
        Intrinsics.checkNotNullParameter(c4113b2, "<this>");
        StudySet studySet = c4113b2.a;
        User user = c4113b2.b;
        String str = user != null ? user.b : null;
        String str2 = str == null ? "" : str;
        String str3 = user != null ? user.i : null;
        String str4 = str3 == null ? "" : str3;
        int iB = user != null ? AbstractC3179j6.b(user) : R.string.empty;
        boolean z = user != null ? user.e : false;
        com.quizlet.generated.enums.J0 j0 = com.quizlet.generated.enums.K0.Companion;
        StudySet studySet2 = c4113b2.a;
        j0.getClass();
        for (com.quizlet.generated.enums.K0 k0 : com.quizlet.generated.enums.K0.values()) {
            if (k0.a() == studySet2.w) {
                com.quizlet.data.model.search.d dVar2 = c4113b2.c;
                if (dVar2 != null) {
                    Intrinsics.checkNotNullParameter(dVar2, "<this>");
                    int i = dVar2.c;
                    if (i != 1) {
                        dVar = i != 10 ? com.quizlet.ui.models.search.d.c : com.quizlet.ui.models.search.d.d;
                    } else {
                        String upperCase = dVar2.d.toUpperCase(Locale.ROOT);
                        Intrinsics.checkNotNullExpressionValue(upperCase, "toUpperCase(...)");
                        dVar = Intrinsics.b(upperCase, "DAY") ? com.quizlet.ui.models.search.d.b : com.quizlet.ui.models.search.d.a;
                    }
                    eVar = new com.quizlet.ui.models.search.e(dVar2.b, dVar, i);
                } else {
                    eVar = null;
                }
                return new com.quizlet.ui.models.content.carditem.f(studySet.a, studySet.h, studySet.n, studySet.o, studySet.s, false, false, str2, str4, iB, z, k0, eVar, 96);
            }
        }
        throw new NoSuchElementException("Array contains no element matching the predicate.");
    }

    public static final com.quizlet.ui.models.content.carditem.g e(com.quizlet.data.model.Z z, boolean z2) {
        Intrinsics.checkNotNullParameter(z, "<this>");
        Textbook textbook = (Textbook) z;
        return new com.quizlet.ui.models.content.carditem.g(textbook.g, textbook.a, textbook.b, textbook.c, textbook.e, textbook.h, textbook.d, textbook.f, z2);
    }

    public static final com.quizlet.ui.models.content.carditem.h f(User user) {
        Intrinsics.checkNotNullParameter(user, "<this>");
        long j = user.a;
        Integer numValueOf = Integer.valueOf(AbstractC3179j6.b(user));
        Integer num = user.m;
        int iIntValue = num != null ? num.intValue() : 0;
        Integer num2 = user.n;
        int iIntValue2 = num2 != null ? num2.intValue() : 0;
        return new com.quizlet.ui.models.content.carditem.h(j, user.i, user.b, user.e, numValueOf, iIntValue, iIntValue2);
    }
}

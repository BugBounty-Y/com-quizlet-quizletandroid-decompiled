package com.google.android.gms.internal.mlkit_vision_common;

import android.os.Bundle;
import android.os.IBinder;
import android.os.Parcel;
import android.os.Parcelable;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.runtime.AbstractC0809m0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;
import androidx.lifecycle.InterfaceC1261w;
import com.google.android.gms.common.internal.safeparcel.SafeParcelReader$ParseException;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3178j5;
import com.google.android.gms.internal.mlkit_vision_barcode.K6;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3405w1;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3417z1;
import com.quizlet.quizletandroid.C4622e;
import java.util.ArrayList;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* renamed from: com.google.android.gms.internal.mlkit_vision_common.i3, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3471i3 {
    public static final void a(com.quizlet.features.settings.viewmodels.p pVar, androidx.navigation.H h, InterfaceC0806l interfaceC0806l, int i) {
        androidx.navigation.H h2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(2014671232);
        int i2 = (c0814p.f(pVar) ? 4 : 2) | i | (c0814p.h(h) ? 32 : 16);
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
            h2 = h;
        } else {
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(androidx.compose.ui.n.b, "SettingsNavHost");
            c0814p.X(1165490155);
            boolean zH = ((i2 & 14) == 4) | c0814p.h(h);
            Object objI = c0814p.I();
            if (zH || objI == C0804k.a) {
                objI = new com.quizlet.features.setpage.header.ui.g(5, h, pVar);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            h2 = h;
            com.google.android.gms.internal.mlkit_vision_camera.Q1.d(h2, "settings", qVarG, (Function1) objI, c0814p, ((i2 >> 3) & 14) | 432, 8);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.questionnaire.screens.d(pVar, h2, i, 10);
        }
    }

    public static final void b(com.quizlet.features.settings.viewmodels.p pVar, androidx.navigation.H h, com.quizlet.quizletandroid.ui.navigationmanagers.h hVar, androidx.compose.material3.windowsizeclass.b bVar, Function0 function0, Function0 function02, InterfaceC0806l interfaceC0806l, int i) {
        com.quizlet.features.settings.viewmodels.p pVar2;
        int i2;
        androidx.navigation.H h2;
        com.quizlet.quizletandroid.ui.navigationmanagers.h hVar2;
        boolean z;
        boolean z2;
        com.quizlet.quizletandroid.ui.navigationmanagers.h hVar3;
        androidx.navigation.H h3;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1884651139);
        int i3 = i | 146 | (c0814p.f(bVar) ? 2048 : 1024) | (c0814p.h(function0) ? 16384 : 8192) | (c0814p.h(function02) ? 131072 : 65536);
        if ((74899 & i3) == 74898 && c0814p.x()) {
            c0814p.Q();
            pVar2 = pVar;
            h3 = h;
            hVar3 = hVar;
        } else {
            c0814p.S();
            int i4 = i & 1;
            androidx.compose.runtime.V v = C0804k.a;
            if (i4 == 0 || c0814p.w()) {
                c0814p.Y(1890788296);
                androidx.lifecycle.C0 c0A = androidx.lifecycle.viewmodel.compose.a.a(c0814p);
                if (c0A == null) {
                    throw new IllegalStateException("No ViewModelStoreOwner was provided via LocalViewModelStoreOwner");
                }
                dagger.hilt.android.internal.lifecycle.f fVarC = AbstractC3405w1.c(c0A, c0814p);
                c0814p.Y(1729797275);
                Object objE = AbstractC3417z1.e(com.quizlet.features.settings.viewmodels.I.class, c0A, null, fVarC, c0A instanceof InterfaceC1261w ? ((InterfaceC1261w) c0A).getDefaultViewModelCreationExtras() : androidx.lifecycle.viewmodel.a.b, c0814p);
                c0814p = c0814p;
                c0814p.p(false);
                c0814p.p(false);
                pVar2 = (com.quizlet.features.settings.viewmodels.p) objE;
                androidx.navigation.H hD = com.google.android.gms.internal.mlkit_vision_camera.O1.d(new androidx.navigation.W[0], c0814p);
                c0814p.X(1907377511);
                Object objB = K6.b(com.quizlet.features.settings.di.a.class, c0814p.j(AndroidCompositionLocals_androidKt.b));
                c0814p.p(false);
                i2 = i3 & (-1023);
                h2 = hD;
                hVar2 = (com.quizlet.quizletandroid.ui.navigationmanagers.h) ((C4622e) ((com.quizlet.features.settings.di.a) objB)).A.get();
            } else {
                c0814p.Q();
                pVar2 = pVar;
                hVar2 = hVar;
                i2 = i3 & (-1023);
                h2 = h;
            }
            c0814p.q();
            com.quizlet.features.settings.viewmodels.I i5 = (com.quizlet.features.settings.viewmodels.I) pVar2;
            kotlinx.coroutines.flow.d0 d0Var = i5.p;
            c0814p.X(1103975363);
            boolean zQ = true;
            boolean zH = ((i2 & 57344) == 16384) | c0814p.h(hVar2) | ((i2 & 458752) == 131072);
            Object objI = c0814p.I();
            if (zH || objI == v) {
                objI = new com.quizlet.features.settings.composables.navigation.g(function0, hVar2, function02, null);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            c0814p.X(-827048655);
            AbstractC0809m0 abstractC0809m0 = androidx.lifecycle.compose.g.a;
            androidx.lifecycle.J j = (androidx.lifecycle.J) c0814p.j(abstractC0809m0);
            androidx.lifecycle.B b = androidx.lifecycle.B.c;
            InterfaceC0773a0 interfaceC0773a0D = C0776c.D((Function2) objI, c0814p);
            Unit unit = Unit.a;
            c0814p.X(1667431386);
            boolean zH2 = c0814p.h(j) | c0814p.h(d0Var) | c0814p.f(b) | c0814p.f(interfaceC0773a0D);
            Object objI2 = c0814p.I();
            if (zH2 || objI2 == v) {
                objI2 = new com.quizlet.features.settings.composables.navigation.d(interfaceC0773a0D, j, null, d0Var);
                c0814p.i0(objI2);
            }
            c0814p.p(false);
            C0776c.f(c0814p, unit, (Function2) objI2);
            c0814p.p(false);
            kotlinx.coroutines.flow.d0 d0Var2 = i5.i.e;
            c0814p.X(1103997699);
            boolean zH3 = c0814p.h(hVar2);
            Object objI3 = c0814p.I();
            if (zH3 || objI3 == v) {
                objI3 = new com.quizlet.features.settings.composables.navigation.h(hVar2, null);
                c0814p.i0(objI3);
            }
            c0814p.p(false);
            c0814p.X(-827048655);
            androidx.lifecycle.J j2 = (androidx.lifecycle.J) c0814p.j(abstractC0809m0);
            InterfaceC0773a0 interfaceC0773a0D2 = C0776c.D((Function2) objI3, c0814p);
            c0814p.X(1667431386);
            boolean zH4 = c0814p.h(j2) | c0814p.h(d0Var2) | c0814p.f(b) | c0814p.f(interfaceC0773a0D2);
            Object objI4 = c0814p.I();
            if (zH4 || objI4 == v) {
                objI4 = new com.quizlet.features.settings.composables.navigation.f(interfaceC0773a0D2, j2, null, d0Var2);
                c0814p.i0(objI4);
            }
            c0814p.p(false);
            C0776c.f(c0814p, unit, (Function2) objI4);
            c0814p.p(false);
            com.quizlet.themes.nighttheme.a aVar = com.quizlet.themes.nighttheme.a.c;
            com.quizlet.quizletandroid.ui.navigationmanagers.h hVar4 = hVar2;
            com.quizlet.themes.nighttheme.a aVar2 = (com.quizlet.themes.nighttheme.a) C0776c.l(i5.o, aVar, null, c0814p, 48, 2).getValue();
            c0814p.X(-1989568620);
            if (aVar2 == aVar) {
                zQ = AbstractC0460p.q(c0814p);
            } else if (aVar2 == com.quizlet.themes.nighttheme.a.d) {
                z = false;
                z2 = false;
                c0814p.p(z);
                androidx.compose.runtime.B b2 = com.quizlet.themes.g.a;
                C0814p c0814p2 = c0814p;
                AbstractC3178j5.b(bVar, z2, new com.quizlet.themes.h(((com.quizlet.themes.b) c0814p.j(b2)).o(), ((com.quizlet.themes.b) c0814p.j(b2)).L()), androidx.compose.runtime.internal.e.e(-1310399779, new com.quizlet.features.practicetest.results.i(13, pVar2, h2), c0814p), c0814p2, ((i2 >> 9) & 14) | 3072, 0);
                c0814p = c0814p2;
                hVar3 = hVar4;
                h3 = h2;
            } else if (aVar2 != com.quizlet.themes.nighttheme.a.e) {
                throw new NoWhenBranchMatchedException();
            }
            z2 = zQ;
            z = false;
            c0814p.p(z);
            androidx.compose.runtime.B b22 = com.quizlet.themes.g.a;
            C0814p c0814p22 = c0814p;
            AbstractC3178j5.b(bVar, z2, new com.quizlet.themes.h(((com.quizlet.themes.b) c0814p.j(b22)).o(), ((com.quizlet.themes.b) c0814p.j(b22)).L()), androidx.compose.runtime.internal.e.e(-1310399779, new com.quizlet.features.practicetest.results.i(13, pVar2, h2), c0814p), c0814p22, ((i2 >> 9) & 14) | 3072, 0);
            c0814p = c0814p22;
            hVar3 = hVar4;
            h3 = h2;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.explanations.questiondetail.ui.composables.e((Object) pVar2, (Object) h3, (Object) hVar3, (Object) bVar, function0, function02, i, 11);
        }
    }

    public static Bundle c(int i, Parcel parcel) {
        int iQ = q(i, parcel);
        int iDataPosition = parcel.dataPosition();
        if (iQ == 0) {
            return null;
        }
        Bundle bundle = parcel.readBundle();
        parcel.setDataPosition(iDataPosition + iQ);
        return bundle;
    }

    public static byte[] d(int i, Parcel parcel) {
        int iQ = q(i, parcel);
        int iDataPosition = parcel.dataPosition();
        if (iQ == 0) {
            return null;
        }
        byte[] bArrCreateByteArray = parcel.createByteArray();
        parcel.setDataPosition(iDataPosition + iQ);
        return bArrCreateByteArray;
    }

    public static ArrayList e(int i, Parcel parcel) {
        int iQ = q(i, parcel);
        int iDataPosition = parcel.dataPosition();
        if (iQ == 0) {
            return null;
        }
        ArrayList arrayList = new ArrayList();
        int i2 = parcel.readInt();
        for (int i3 = 0; i3 < i2; i3++) {
            arrayList.add(Integer.valueOf(parcel.readInt()));
        }
        parcel.setDataPosition(iDataPosition + iQ);
        return arrayList;
    }

    public static Parcelable f(Parcel parcel, int i, Parcelable.Creator creator) {
        int iQ = q(i, parcel);
        int iDataPosition = parcel.dataPosition();
        if (iQ == 0) {
            return null;
        }
        Parcelable parcelable = (Parcelable) creator.createFromParcel(parcel);
        parcel.setDataPosition(iDataPosition + iQ);
        return parcelable;
    }

    public static String g(int i, Parcel parcel) {
        int iQ = q(i, parcel);
        int iDataPosition = parcel.dataPosition();
        if (iQ == 0) {
            return null;
        }
        String string = parcel.readString();
        parcel.setDataPosition(iDataPosition + iQ);
        return string;
    }

    public static String[] h(int i, Parcel parcel) {
        int iQ = q(i, parcel);
        int iDataPosition = parcel.dataPosition();
        if (iQ == 0) {
            return null;
        }
        String[] strArrCreateStringArray = parcel.createStringArray();
        parcel.setDataPosition(iDataPosition + iQ);
        return strArrCreateStringArray;
    }

    public static ArrayList i(int i, Parcel parcel) {
        int iQ = q(i, parcel);
        int iDataPosition = parcel.dataPosition();
        if (iQ == 0) {
            return null;
        }
        ArrayList<String> arrayListCreateStringArrayList = parcel.createStringArrayList();
        parcel.setDataPosition(iDataPosition + iQ);
        return arrayListCreateStringArrayList;
    }

    public static Object[] j(Parcel parcel, int i, Parcelable.Creator creator) {
        int iQ = q(i, parcel);
        int iDataPosition = parcel.dataPosition();
        if (iQ == 0) {
            return null;
        }
        Object[] objArrCreateTypedArray = parcel.createTypedArray(creator);
        parcel.setDataPosition(iDataPosition + iQ);
        return objArrCreateTypedArray;
    }

    public static ArrayList k(Parcel parcel, int i, Parcelable.Creator creator) {
        int iQ = q(i, parcel);
        int iDataPosition = parcel.dataPosition();
        if (iQ == 0) {
            return null;
        }
        ArrayList arrayListCreateTypedArrayList = parcel.createTypedArrayList(creator);
        parcel.setDataPosition(iDataPosition + iQ);
        return arrayListCreateTypedArrayList;
    }

    public static void l(int i, Parcel parcel) {
        if (parcel.dataPosition() == i) {
            return;
        }
        StringBuilder sb = new StringBuilder(String.valueOf(i).length() + 26);
        sb.append("Overread allowed size end=");
        sb.append(i);
        throw new SafeParcelReader$ParseException(sb.toString(), parcel);
    }

    public static boolean m(int i, Parcel parcel) {
        t(parcel, i, 4);
        return parcel.readInt() != 0;
    }

    public static IBinder n(int i, Parcel parcel) {
        int iQ = q(i, parcel);
        int iDataPosition = parcel.dataPosition();
        if (iQ == 0) {
            return null;
        }
        IBinder strongBinder = parcel.readStrongBinder();
        parcel.setDataPosition(iDataPosition + iQ);
        return strongBinder;
    }

    public static int o(int i, Parcel parcel) {
        t(parcel, i, 4);
        return parcel.readInt();
    }

    public static long p(int i, Parcel parcel) {
        t(parcel, i, 8);
        return parcel.readLong();
    }

    public static int q(int i, Parcel parcel) {
        return (i & (-65536)) != -65536 ? (char) (i >> 16) : parcel.readInt();
    }

    public static void r(int i, Parcel parcel) {
        parcel.setDataPosition(parcel.dataPosition() + q(i, parcel));
    }

    public static int s(Parcel parcel) {
        int i = parcel.readInt();
        int iQ = q(i, parcel);
        char c = (char) i;
        int iDataPosition = parcel.dataPosition();
        if (c != 20293) {
            throw new SafeParcelReader$ParseException("Expected object header. Got 0x".concat(String.valueOf(Integer.toHexString(i))), parcel);
        }
        int i2 = iQ + iDataPosition;
        if (i2 >= iDataPosition && i2 <= parcel.dataSize()) {
            return i2;
        }
        StringBuilder sb = new StringBuilder(String.valueOf(iDataPosition).length() + 32 + String.valueOf(i2).length());
        sb.append("Size read is invalid start=");
        sb.append(iDataPosition);
        sb.append(" end=");
        sb.append(i2);
        throw new SafeParcelReader$ParseException(sb.toString(), parcel);
    }

    public static void t(Parcel parcel, int i, int i2) {
        int iQ = q(i, parcel);
        if (iQ == i2) {
            return;
        }
        String hexString = Integer.toHexString(iQ);
        int length = String.valueOf(i2).length();
        StringBuilder sb = new StringBuilder(String.valueOf(hexString).length() + length + 19 + String.valueOf(iQ).length() + 4 + 1);
        sb.append("Expected size ");
        sb.append(i2);
        sb.append(" got ");
        sb.append(iQ);
        throw new SafeParcelReader$ParseException(AbstractC0147y.g(sb, " (0x", hexString, ")"), parcel);
    }

    public static void u(Parcel parcel, int i, int i2) {
        if (i == i2) {
            return;
        }
        String hexString = Integer.toHexString(i);
        int length = String.valueOf(i2).length();
        StringBuilder sb = new StringBuilder(String.valueOf(hexString).length() + length + 19 + String.valueOf(i).length() + 4 + 1);
        sb.append("Expected size ");
        sb.append(i2);
        sb.append(" got ");
        sb.append(i);
        throw new SafeParcelReader$ParseException(AbstractC0147y.g(sb, " (0x", hexString, ")"), parcel);
    }
}

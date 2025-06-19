package com.quizlet.features.flashcards.navigation;

import android.content.Context;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.runtime.V;
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;
import androidx.navigation.E;
import androidx.navigation.H;
import androidx.navigation.W;
import androidx.navigation.compose.w;
import com.google.android.gms.internal.mlkit_vision_barcode.K6;
import com.google.android.gms.internal.mlkit_vision_barcode.N5;
import com.google.android.gms.internal.mlkit_vision_camera.O1;
import com.google.android.gms.internal.mlkit_vision_camera.Q1;
import com.quizlet.assembly.compose.input.m;
import com.quizlet.features.flashcards.S;
import com.quizlet.features.infra.models.studymodeshared.StudyableModelData;
import com.quizlet.quizletandroid.C4622e;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class d {
    public static final /* synthetic */ int a = 0;
    public static final /* synthetic */ int b = 0;

    public static final void a(final int i, final StudyableModelData studyableModelData, final long j, final String title, final boolean z, final String screenName, H h, com.quizlet.quizletandroid.ui.studymodes.flashcards.navigation.a aVar, final S s, InterfaceC0806l interfaceC0806l, final int i2) {
        H hD;
        int i3;
        final com.quizlet.quizletandroid.ui.studymodes.flashcards.navigation.a aVar2;
        final H h2;
        C0814p c0814p;
        Intrinsics.checkNotNullParameter(studyableModelData, "studyableModelData");
        Intrinsics.checkNotNullParameter(title, "title");
        Intrinsics.checkNotNullParameter(screenName, "screenName");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(419654601);
        int i4 = i2 | (c0814p2.d(i) ? 4 : 2) | (c0814p2.h(studyableModelData) ? 32 : 16) | (c0814p2.e(j) ? 256 : 128) | (c0814p2.f(title) ? 2048 : 1024) | (c0814p2.g(z) ? 16384 : 8192) | (c0814p2.f(screenName) ? 131072 : 65536) | 4718592 | (c0814p2.h(s) ? 67108864 : 33554432);
        if ((38347923 & i4) == 38347922 && c0814p2.x()) {
            c0814p2.Q();
            h2 = h;
            aVar2 = aVar;
            c0814p = c0814p2;
        } else {
            c0814p2.S();
            if ((i2 & 1) == 0 || c0814p2.w()) {
                hD = O1.d(new W[0], c0814p2);
                c0814p2.X(1907377511);
                Object objB = K6.b(com.quizlet.features.flashcards.di.a.class, c0814p2.j(AndroidCompositionLocals_androidKt.b));
                c0814p2.p(false);
                i3 = i4 & (-33030145);
                aVar2 = (com.quizlet.quizletandroid.ui.studymodes.flashcards.navigation.a) ((C4622e) ((com.quizlet.features.flashcards.di.a) objB)).k.get();
            } else {
                c0814p2.Q();
                i3 = i4 & (-33030145);
                hD = h;
                aVar2 = aVar;
            }
            c0814p2.q();
            Context context = (Context) c0814p2.j(AndroidCompositionLocals_androidKt.b);
            c0814p2.X(938467212);
            Object objI = c0814p2.I();
            V v = C0804k.a;
            if (objI == v) {
                objI = new w(context, 3);
                c0814p2.i0(objI);
            }
            final Function0 function0 = (Function0) objI;
            c0814p2.p(false);
            c0814p2.X(938473286);
            boolean zH = ((i3 & 14) == 4) | c0814p2.h(studyableModelData) | ((i3 & 896) == 256) | ((i3 & 7168) == 2048) | ((57344 & i3) == 16384) | ((i3 & 458752) == 131072) | c0814p2.h(hD) | c0814p2.h(aVar2) | c0814p2.h(s);
            Object objI2 = c0814p2.I();
            if (zH || objI2 == v) {
                h2 = hD;
                Function1 function1 = new Function1() { // from class: com.quizlet.features.flashcards.navigation.a
                    @Override // kotlin.jvm.functions.Function1
                    public final Object invoke(Object obj) {
                        E NavHost = (E) obj;
                        Intrinsics.checkNotNullParameter(NavHost, "$this$NavHost");
                        f fVar = new f(i, j, studyableModelData, title, screenName, z);
                        H h3 = h2;
                        com.quizlet.quizletandroid.ui.studymodes.flashcards.navigation.a aVar3 = aVar2;
                        Function0 function02 = function0;
                        S s2 = s;
                        N5.d(NavHost, fVar, new androidx.compose.runtime.internal.d(true, -1007753076, new com.quizlet.assembly.compose.menu.g((Object) h3, (Object) aVar3, (Object) function02, (Object) s2, 2)));
                        N5.e(NavHost, g.a, new androidx.compose.runtime.internal.d(true, -234923129, new m(6, h3, s2)));
                        return Unit.a;
                    }
                };
                c0814p2.i0(function1);
                objI2 = function1;
            } else {
                h2 = hD;
            }
            c0814p2.p(false);
            c0814p = c0814p2;
            Q1.d(h2, "flashcards", null, (Function1) objI2, c0814p, 48, 12);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new Function2(i, studyableModelData, j, title, z, screenName, h2, aVar2, s, i2) { // from class: com.quizlet.features.flashcards.navigation.b
                public final /* synthetic */ int a;
                public final /* synthetic */ StudyableModelData b;
                public final /* synthetic */ long c;
                public final /* synthetic */ String d;
                public final /* synthetic */ boolean e;
                public final /* synthetic */ String f;
                public final /* synthetic */ H g;
                public final /* synthetic */ com.quizlet.quizletandroid.ui.studymodes.flashcards.navigation.a h;
                public final /* synthetic */ S i;

                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(Object obj, Object obj2) {
                    ((Integer) obj2).getClass();
                    int iH = C0776c.H(1);
                    StudyableModelData studyableModelData2 = this.b;
                    String str = this.d;
                    String str2 = this.f;
                    com.quizlet.quizletandroid.ui.studymodes.flashcards.navigation.a aVar3 = this.h;
                    S s2 = this.i;
                    d.a(this.a, studyableModelData2, this.c, str, this.e, str2, this.g, aVar3, s2, (InterfaceC0806l) obj, iH);
                    return Unit.a;
                }
            };
        }
    }
}

package com.quizlet.features.flashcards.settings.ui;

import androidx.compose.material3.O3;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.n;
import androidx.navigation.H;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3209n0;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3394t2;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3625g4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.F4;
import com.quizlet.features.flashcards.settings.k;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.C4739h;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.L;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.W;

/* loaded from: classes2.dex */
public final /* synthetic */ class a implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;
    public final /* synthetic */ Object e;
    public final /* synthetic */ Object f;
    public final /* synthetic */ Object g;
    public final /* synthetic */ Object h;
    public final /* synthetic */ Object i;
    public final /* synthetic */ Object j;

    public /* synthetic */ a(Object obj, Object obj2, Object obj3, Object obj4, Object obj5, Object obj6, Object obj7, Object obj8, Object obj9, int i, int i2) {
        this.a = i2;
        this.e = obj;
        this.c = obj2;
        this.f = obj3;
        this.g = obj4;
        this.h = obj5;
        this.i = obj6;
        this.j = obj7;
        this.b = obj8;
        this.d = obj9;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(100663297);
                Function0 function0 = (Function0) this.b;
                Function0 function02 = (Function0) this.d;
                AbstractC3209n0.a((k) this.e, (Function1) this.c, (Function1) this.f, (Function1) this.g, (Function1) this.h, (Function1) this.i, (Function1) this.j, function0, function02, (InterfaceC0806l) obj, iH);
                break;
            case 1:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(100859905);
                Function1 function1 = (Function1) this.c;
                Function0 function03 = (Function0) this.d;
                AbstractC3394t2.d((W) this.e, (com.quizlet.features.practicetest.takingtest.viewmodel.a) this.f, (Function2) this.g, (Function2) this.h, (Function2) this.i, (Function0) this.b, (Function2) this.j, function1, function03, (InterfaceC0806l) obj, iH2);
                break;
            case 2:
                ((Integer) obj2).getClass();
                int iH3 = C0776c.H(1);
                Function1 function12 = (Function1) this.g;
                com.quizlet.login.signup.viewmodel.a aVar = (com.quizlet.login.signup.viewmodel.a) this.j;
                AbstractC3625g4.d((Function0) this.b, (Function0) this.d, (Function0) this.e, (Function1) this.c, (Function0) this.h, (Function0) this.i, (Function1) this.f, function12, aVar, (InterfaceC0806l) obj, iH3);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH4 = C0776c.H(1);
                H h = (H) this.b;
                O3 o3 = (O3) this.d;
                F4.a((n) this.e, (com.quizlet.quizletandroid.ui.globalnav.viewmodel.e) this.c, (L) this.f, (C4739h) this.g, (com.quizlet.features.infra.snackbar.viewmodel.c) this.h, (com.quizlet.quizletandroid.ui.globalnav.navigation.a) this.i, (androidx.compose.material.navigation.i) this.j, h, o3, (InterfaceC0806l) obj, iH4);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ a(Function0 function0, Function0 function02, Function0 function03, Function1 function1, Function0 function04, Function0 function05, Function1 function12, Function1 function13, com.quizlet.login.signup.viewmodel.a aVar, int i) {
        this.a = 2;
        this.b = function0;
        this.d = function02;
        this.e = function03;
        this.c = function1;
        this.h = function04;
        this.i = function05;
        this.f = function12;
        this.g = function13;
        this.j = aVar;
    }

    public /* synthetic */ a(W w, com.quizlet.features.practicetest.takingtest.viewmodel.a aVar, Function2 function2, Function2 function22, Function2 function23, Function0 function0, Function2 function24, Function1 function1, Function0 function02, int i) {
        this.a = 1;
        this.e = w;
        this.f = aVar;
        this.g = function2;
        this.h = function22;
        this.i = function23;
        this.b = function0;
        this.j = function24;
        this.c = function1;
        this.d = function02;
    }
}

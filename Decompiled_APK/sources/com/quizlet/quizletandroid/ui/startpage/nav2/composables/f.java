package com.quizlet.quizletandroid.ui.startpage.nav2.composables;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.n;
import androidx.compose.ui.q;
import androidx.navigation.H;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3244r0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3285w0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3309z0;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3579a6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3714r6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3730t6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3762x6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.C6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.U6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.Z6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.b7;
import com.google.android.gms.internal.mlkit_vision_document_scanner.e7;
import com.google.android.gms.internal.mlkit_vision_document_scanner.f7;
import com.google.firebase.crashlytics.internal.model.u0;
import com.quizlet.data.model.B2;
import com.quizlet.data.model.C2;
import com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.m;
import com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.LearnSettingsIntentData;
import kotlin.InterfaceC4938g;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final /* synthetic */ class f implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;

    public /* synthetic */ f(int i, int i2, Object obj, Object obj2, Object obj3) {
        this.a = i2;
        this.c = obj;
        this.d = obj2;
        this.b = obj3;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        int i = this.a;
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
        ((Integer) obj2).getClass();
        switch (i) {
            case 0:
                int iH = C0776c.H(1);
                AbstractC3579a6.a((kotlinx.collections.immutable.b) this.c, (n) this.d, (Function1) this.b, interfaceC0806l, iH);
                break;
            case 1:
                int iH2 = C0776c.H(1);
                AbstractC3714r6.a((com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.n) this.c, (q) this.d, (Function1) this.b, interfaceC0806l, iH2);
                break;
            case 2:
                int iH3 = C0776c.H(1);
                AbstractC3730t6.a((m) this.c, (q) this.d, (Function1) this.b, interfaceC0806l, iH3);
                break;
            case 3:
                int iH4 = C0776c.H(9);
                AbstractC3762x6.a((com.quizlet.learn.ui.g) this.c, (Function1) this.b, (q) this.d, interfaceC0806l, iH4);
                break;
            case 4:
                int iH5 = C0776c.H(1);
                C6.a((Function1) this.b, (n) this.d, (com.quizlet.quizletandroid.ui.studymodes.assistant.settings.viewmodel.a) this.c, interfaceC0806l, iH5);
                break;
            case 5:
                com.quizlet.quizletandroid.ui.studymodes.assistant.settings.navigation.b.a((LearnSettingsIntentData) this.c, (H) this.d, (com.quizlet.quizletandroid.ui.navigationmanagers.c) this.b, interfaceC0806l, C0776c.H(1));
                break;
            case 6:
                int iH6 = C0776c.H(1);
                U6.a((com.quizlet.quizletandroid.ui.studymodes.testmode.studyengine.g) this.c, (q) this.d, (Function1) this.b, interfaceC0806l, iH6);
                break;
            case 7:
                Z6.b((e7) this.c, (q) this.d, (Function1) this.b, interfaceC0806l, C0776c.H(1));
                break;
            case 8:
                b7.b((f7) this.c, (q) this.d, (Function1) this.b, interfaceC0806l, C0776c.H(1));
                break;
            case 9:
                int iH7 = C0776c.H(1);
                u0.a((Function0) this.c, (Function0) this.b, (n) this.d, interfaceC0806l, iH7);
                break;
            case 10:
                int iH8 = C0776c.H(1);
                com.google.mlkit.common.model.a.g((com.quizlet.quizletandroid.ui.subject.viewmodel.g) this.c, (Function2) this.d, (Function1) this.b, interfaceC0806l, iH8);
                break;
            case 11:
                com.quizlet.login.common.navigation.e.a((C2) this.c, (androidx.appcompat.view.a) this.d, (androidx.glance.n) this.b, interfaceC0806l, C0776c.H(1));
                break;
            case 12:
                int iH9 = C0776c.H(1);
                _COROUTINE.a.e((C2) this.c, (B2) this.d, (androidx.appcompat.view.a) this.b, interfaceC0806l, iH9);
                break;
            case 13:
                int iH10 = C0776c.H(49);
                AbstractC3244r0.b((com.quizlet.search.data.b) this.c, (q) this.d, (Function1) this.b, interfaceC0806l, iH10);
                break;
            case 14:
                int iH11 = C0776c.H(1);
                AbstractC3285w0.b((com.quizlet.ui.models.search.c) this.c, (Function1) this.b, (n) this.d, interfaceC0806l, iH11);
                break;
            default:
                int iH12 = C0776c.H(1);
                AbstractC3309z0.a((com.quizlet.search.data.typeahead.a) this.c, (n) this.d, (Function1) this.b, interfaceC0806l, iH12);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ f(Object obj, InterfaceC4938g interfaceC4938g, q qVar, int i, int i2) {
        this.a = i2;
        this.c = obj;
        this.b = interfaceC4938g;
        this.d = qVar;
    }

    public /* synthetic */ f(Function1 function1, n nVar, com.quizlet.quizletandroid.ui.studymodes.assistant.settings.viewmodel.a aVar, int i) {
        this.a = 4;
        this.b = function1;
        this.d = nVar;
        this.c = aVar;
    }
}

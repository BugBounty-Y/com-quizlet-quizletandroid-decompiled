package com.quizlet.features.achievements.ui.composables;

import androidx.compose.foundation.pager.C0466e;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.lifecycle.Y;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3107b6;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3205m5;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3215n6;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3259s6;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3277v0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3314z5;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3315z6;
import com.google.android.gms.internal.mlkit_vision_barcode.C5;
import com.google.android.gms.internal.mlkit_vision_barcode.D0;
import com.google.android.gms.internal.mlkit_vision_camera.A1;
import com.google.android.gms.internal.mlkit_vision_camera.N1;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3531s4;
import com.google.android.gms.internal.mlkit_vision_common.Q2;
import com.google.android.gms.internal.mlkit_vision_common.z4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3722s6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.h7;
import kotlin.InterfaceC4938g;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* renamed from: com.quizlet.features.achievements.ui.composables.e, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class C4218e implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ int c;
    public final /* synthetic */ int d;
    public final /* synthetic */ Object e;
    public final /* synthetic */ Object f;

    public /* synthetic */ C4218e(int i, int i2, int i3, androidx.compose.ui.q qVar, Object obj, Object obj2) {
        this.a = i3;
        this.e = obj;
        this.f = obj2;
        this.b = qVar;
        this.c = i;
        this.d = i2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(this.d | 1);
                androidx.compose.ui.q qVar = (androidx.compose.ui.q) this.b;
                int i = this.c;
                com.facebook.appevents.m.a((androidx.camera.core.impl.utils.e) this.e, (Function0) this.f, qVar, i, (InterfaceC0806l) obj, iH);
                break;
            case 1:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(this.d | 1);
                androidx.compose.ui.q qVar2 = (androidx.compose.ui.q) this.b;
                int i2 = this.c;
                AbstractC3205m5.a((kotlinx.collections.immutable.e) this.e, (Function1) this.f, qVar2, i2, (InterfaceC0806l) obj, iH2);
                break;
            case 2:
                ((Integer) obj2).getClass();
                int iH3 = C0776c.H(9);
                com.quizlet.features.infra.basestudy.ui.models.a aVar = (com.quizlet.features.infra.basestudy.ui.models.a) this.e;
                int i3 = this.c;
                AbstractC3314z5.a(aVar, (androidx.compose.ui.q) this.b, (Function1) this.f, i3, (InterfaceC0806l) obj, iH3, this.d);
                break;
            case 3:
                ((Integer) obj2).getClass();
                int iH4 = C0776c.H(this.c | 1);
                Function1 function1 = (Function1) this.f;
                AbstractC3259s6.b((com.quizlet.features.infra.folder.tag.screenstates.k) this.e, (androidx.compose.ui.q) this.b, function1, (InterfaceC0806l) obj, iH4, this.d);
                break;
            case 4:
                ((Integer) obj2).getClass();
                int iH5 = C0776c.H(this.c | 1);
                com.quizlet.features.infra.logout.composables.a aVar2 = (com.quizlet.features.infra.logout.composables.a) this.e;
                Function0 function0 = (Function0) this.f;
                AbstractC3315z6.a(aVar2, (Function1) this.b, function0, (InterfaceC0806l) obj, iH5, this.d);
                break;
            case 5:
                ((Integer) obj2).getClass();
                int iH6 = C0776c.H(this.c | 1);
                androidx.compose.ui.n nVar = (androidx.compose.ui.n) this.b;
                A1.c((Function0) this.f, (Function1) this.e, nVar, (InterfaceC0806l) obj, iH6, this.d);
                break;
            case 6:
                ((Integer) obj2).intValue();
                N1.d((androidx.compose.ui.text.input.A) this.e, this.c, (Function0) this.f, (Function1) this.b, (InterfaceC0806l) obj, C0776c.H(this.d | 1));
                break;
            case 7:
                ((Integer) obj2).getClass();
                int iH7 = C0776c.H(this.c | 1);
                Function0 function02 = (Function0) this.f;
                Q2.b((com.quizlet.themes.nighttheme.a) this.e, (Function1) this.b, function02, (InterfaceC0806l) obj, iH7, this.d);
                break;
            case 8:
                ((Integer) obj2).getClass();
                int iH8 = C0776c.H(this.d | 1);
                Function0 function03 = (Function0) this.f;
                Function0 function04 = (Function0) this.b;
                AbstractC3531s4.d(this.c, (String) this.e, function03, function04, (InterfaceC0806l) obj, iH8);
                break;
            case 9:
                ((Integer) obj2).getClass();
                int iH9 = C0776c.H(this.c | 1);
                Function0 function05 = (Function0) this.f;
                z4.d((String) this.e, (com.quizlet.learn.viewmodel.i) this.b, function05, (InterfaceC0806l) obj, iH9, this.d);
                break;
            case 10:
                ((Integer) obj2).getClass();
                int iH10 = C0776c.H(this.c | 1);
                androidx.compose.ui.graphics.painter.b bVar = (androidx.compose.ui.graphics.painter.b) this.f;
                AbstractC3722s6.c((String) this.e, (androidx.compose.ui.q) this.b, bVar, (InterfaceC0806l) obj, iH10, this.d);
                break;
            case 11:
                ((Integer) obj2).getClass();
                int iH11 = C0776c.H(this.d | 1);
                com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.y yVar = (com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.y) this.f;
                int i4 = this.c;
                androidx.compose.ui.q qVar3 = (androidx.compose.ui.q) this.b;
                h7.e((androidx.compose.ui.text.input.A) this.e, yVar, i4, qVar3, (InterfaceC0806l) obj, iH11);
                break;
            case 12:
                ((Integer) obj2).getClass();
                int iH12 = C0776c.H(this.d | 1);
                Object obj3 = this.f;
                Function1 function12 = (Function1) this.b;
                AbstractC3277v0.c(this.c, (Enum) this.e, obj3, function12, (InterfaceC0806l) obj, iH12);
                break;
            case 13:
                ((Integer) obj2).getClass();
                int iH13 = C0776c.H(this.d | 1);
                Function2 function2 = (Function2) this.b;
                Function0 function06 = (Function0) this.f;
                D0.h((com.quizlet.search.data.term.h) this.e, this.c, function2, function06, (InterfaceC0806l) obj, iH13);
                break;
            case 14:
                ((Integer) obj2).getClass();
                int iH14 = C0776c.H(this.d | 1);
                Function2 function22 = (Function2) this.b;
                Function0 function07 = (Function0) this.f;
                D0.g((com.quizlet.search.data.term.f) this.e, this.c, function22, function07, (InterfaceC0806l) obj, iH14);
                break;
            case 15:
                ((Integer) obj2).getClass();
                int iH15 = C0776c.H(this.c | 1);
                androidx.compose.ui.q qVar4 = (androidx.compose.ui.q) this.b;
                C5.b((kotlinx.collections.immutable.b) this.e, (C0466e) this.f, qVar4, (InterfaceC0806l) obj, iH15, this.d);
                break;
            case 16:
                ((Integer) obj2).getClass();
                int iH16 = C0776c.H(1);
                Y y = (Y) this.e;
                Function0 function08 = (Function0) this.f;
                int i5 = this.c;
                int i6 = this.d;
                AbstractC3107b6.a(y, function08, (androidx.compose.ui.n) this.b, i5, i6, (InterfaceC0806l) obj, iH16);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH17 = C0776c.H(3073);
                String str = (String) this.b;
                Function0 function09 = (Function0) this.f;
                AbstractC3215n6.a((androidx.compose.ui.graphics.painter.b) this.e, this.c, this.d, str, function09, (InterfaceC0806l) obj, iH17);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ C4218e(int i, int i2, int i3, Object obj, Object obj2, Object obj3) {
        this.a = i3;
        this.e = obj;
        this.b = obj2;
        this.f = obj3;
        this.c = i;
        this.d = i2;
    }

    public /* synthetic */ C4218e(int i, int i2, int i3, Object obj, Object obj2, InterfaceC4938g interfaceC4938g) {
        this.a = i3;
        this.c = i;
        this.e = obj;
        this.f = obj2;
        this.b = interfaceC4938g;
        this.d = i2;
    }

    public /* synthetic */ C4218e(androidx.compose.ui.graphics.painter.b bVar, int i, int i2, String str, Function0 function0, int i3) {
        this.a = 17;
        this.e = bVar;
        this.c = i;
        this.d = i2;
        this.b = str;
        this.f = function0;
    }

    public /* synthetic */ C4218e(androidx.compose.ui.text.input.A a, int i, Function0 function0, Function1 function1, int i2) {
        this.a = 6;
        this.e = a;
        this.c = i;
        this.f = function0;
        this.b = function1;
        this.d = i2;
    }

    public /* synthetic */ C4218e(androidx.compose.ui.text.input.A a, com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.y yVar, int i, androidx.compose.ui.q qVar, int i2) {
        this.a = 11;
        this.e = a;
        this.f = yVar;
        this.c = i;
        this.b = qVar;
        this.d = i2;
    }

    public /* synthetic */ C4218e(Y y, Function0 function0, androidx.compose.ui.n nVar, int i, int i2, int i3) {
        this.a = 16;
        this.e = y;
        this.f = function0;
        this.b = nVar;
        this.c = i;
        this.d = i2;
    }

    public /* synthetic */ C4218e(com.quizlet.features.infra.basestudy.ui.models.a aVar, androidx.compose.ui.q qVar, Function1 function1, int i, int i2, int i3) {
        this.a = 2;
        this.e = aVar;
        this.b = qVar;
        this.f = function1;
        this.c = i;
        this.d = i3;
    }

    public /* synthetic */ C4218e(com.quizlet.search.data.term.h hVar, int i, Function2 function2, Function0 function0, int i2, int i3) {
        this.a = i3;
        this.e = hVar;
        this.c = i;
        this.b = function2;
        this.f = function0;
        this.d = i2;
    }

    public /* synthetic */ C4218e(Function0 function0, Function1 function1, androidx.compose.ui.n nVar, int i, int i2) {
        this.a = 5;
        this.f = function0;
        this.e = function1;
        this.b = nVar;
        this.c = i;
        this.d = i2;
    }
}

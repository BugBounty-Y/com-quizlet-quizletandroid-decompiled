package com.quizlet.quizletandroid.ui.studymodes.testmode.start;

import android.view.MotionEvent;
import android.view.View;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3119d0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3214n5;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3277v0;
import com.google.android.gms.internal.mlkit_vision_barcode.N4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.h7;
import com.quizlet.data.model.B2;
import com.quizlet.data.model.C2;
import com.quizlet.data.model.D2;
import com.quizlet.data.model.x2;
import com.quizlet.generated.enums.EnumC4484g1;
import com.quizlet.generated.enums.EnumC4490i1;
import com.quizlet.generated.enums.Y0;
import com.skydoves.balloon.Balloon;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final /* synthetic */ class p implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;

    public /* synthetic */ p(View view, Balloon balloon) {
        this.a = 12;
        this.b = view;
        this.c = balloon;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(1);
                h7.j((A) this.b, (B) this.c, (InterfaceC0806l) obj, iH);
                return Unit.a;
            case 1:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(1);
                androidx.appcompat.view.a aVar = (androidx.appcompat.view.a) this.c;
                org.jsoup.helper.b.c((x2) this.b, aVar, (InterfaceC0806l) obj, iH2);
                return Unit.a;
            case 2:
                ((Integer) obj2).getClass();
                int iH3 = C0776c.H(1);
                androidx.appcompat.view.a aVar2 = (androidx.appcompat.view.a) this.c;
                org.jsoup.helper.b.a((D2) this.b, aVar2, (InterfaceC0806l) obj, iH3);
                return Unit.a;
            case 3:
                ((Integer) obj2).getClass();
                int iH4 = C0776c.H(1);
                _COROUTINE.a.a((C2) this.b, (androidx.appcompat.view.a) this.c, (InterfaceC0806l) obj, iH4);
                return Unit.a;
            case 4:
                ((Integer) obj2).getClass();
                int iH5 = C0776c.H(1);
                androidx.appcompat.view.a aVar3 = (androidx.appcompat.view.a) this.c;
                _COROUTINE.a.b((B2) this.b, aVar3, (InterfaceC0806l) obj, iH5);
                return Unit.a;
            case 5:
                ((Integer) obj2).getClass();
                int iH6 = C0776c.H(1);
                AbstractC3119d0.d((Function1) this.b, (com.quizlet.report.viewmodels.a) this.c, (InterfaceC0806l) obj, iH6);
                return Unit.a;
            case 6:
                ((Integer) obj2).getClass();
                int iH7 = C0776c.H(1);
                AbstractC3277v0.f((Y0) this.b, (Function1) this.c, (InterfaceC0806l) obj, iH7);
                return Unit.a;
            case 7:
                ((Integer) obj2).getClass();
                int iH8 = C0776c.H(1);
                AbstractC3277v0.g((com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.w) this.b, (androidx.compose.ui.n) this.c, (InterfaceC0806l) obj, iH8);
                return Unit.a;
            case 8:
                ((Integer) obj2).getClass();
                int iH9 = C0776c.H(1);
                AbstractC3277v0.h((EnumC4484g1) this.b, (Function1) this.c, (InterfaceC0806l) obj, iH9);
                return Unit.a;
            case 9:
                ((Integer) obj2).getClass();
                int iH10 = C0776c.H(1);
                AbstractC3277v0.e((EnumC4490i1) this.b, (Function1) this.c, (InterfaceC0806l) obj, iH10);
                return Unit.a;
            case 10:
                ((Integer) obj2).getClass();
                int iH11 = C0776c.H(1);
                N4.e((com.quizlet.security.challenge.viewmodel.d) this.b, (androidx.compose.ui.n) this.c, (InterfaceC0806l) obj, iH11);
                return Unit.a;
            case 11:
                ((Integer) obj2).getClass();
                int iH12 = C0776c.H(1);
                AbstractC3214n5.a((com.google.android.gms.ads.k) this.b, (androidx.compose.ui.n) this.c, (InterfaceC0806l) obj, iH12);
                return Unit.a;
            default:
                Balloon balloon = (Balloon) this.c;
                return Boolean.valueOf(Balloon.passTouchEventToAnchor$lambda$50((View) this.b, balloon, (View) obj, (MotionEvent) obj2));
        }
    }

    public /* synthetic */ p(Object obj, Object obj2, int i, int i2) {
        this.a = i2;
        this.b = obj;
        this.c = obj2;
    }
}

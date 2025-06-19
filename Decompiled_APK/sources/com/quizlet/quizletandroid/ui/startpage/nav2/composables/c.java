package com.quizlet.quizletandroid.ui.startpage.nav2.composables;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_document_scanner.Y5;
import com.quizlet.quizletandroid.ui.startpage.nav2.model.C4716l;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final /* synthetic */ class c implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ C4716l b;
    public final /* synthetic */ Function0 c;
    public final /* synthetic */ Function0 d;
    public final /* synthetic */ Function0 e;
    public final /* synthetic */ Function0 f;
    public final /* synthetic */ Function0 g;
    public final /* synthetic */ int h;

    public /* synthetic */ c(C4716l c4716l, Function0 function0, Function0 function02, Function0 function03, Function0 function04, Function0 function05, int i, int i2) {
        this.a = 0;
        this.b = c4716l;
        this.c = function0;
        this.d = function02;
        this.e = function03;
        this.f = function04;
        this.g = function05;
        this.h = i2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(1);
                Function0 function0 = this.g;
                int i = this.h;
                Y5.b(this.b, this.c, this.d, this.e, this.f, function0, (InterfaceC0806l) obj, iH, i);
                break;
            case 1:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(this.h | 1);
                Function0 function02 = this.f;
                Function0 function03 = this.g;
                Y5.c(this.b, this.c, this.d, this.e, function02, function03, (InterfaceC0806l) obj, iH2);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH3 = C0776c.H(this.h | 1);
                Function0 function04 = this.f;
                Function0 function05 = this.g;
                Y5.e(this.b, this.c, this.d, this.e, function04, function05, (InterfaceC0806l) obj, iH3);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ c(C4716l c4716l, Function0 function0, Function0 function02, Function0 function03, Function0 function04, Function0 function05, int i, int i2, byte b) {
        this.a = i2;
        this.b = c4716l;
        this.c = function0;
        this.d = function02;
        this.e = function03;
        this.f = function04;
        this.g = function05;
        this.h = i;
    }
}

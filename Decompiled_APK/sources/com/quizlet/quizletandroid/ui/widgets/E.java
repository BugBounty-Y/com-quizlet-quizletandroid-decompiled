package com.quizlet.quizletandroid.ui.widgets;

import androidx.compose.runtime.InterfaceC0806l;
import com.quizlet.data.model.B2;
import com.quizlet.data.model.C2;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class E implements kotlin.jvm.functions.c {
    public final /* synthetic */ int a = 1;
    public final /* synthetic */ C2 b;
    public final /* synthetic */ androidx.appcompat.view.a c;
    public final /* synthetic */ B2 d;

    public E(C2 c2, androidx.appcompat.view.a aVar, B2 b2) {
        this.b = c2;
        this.c = aVar;
        this.d = b2;
    }

    @Override // kotlin.jvm.functions.c
    public final Object invoke(Object obj, Object obj2, Object obj3) {
        switch (this.a) {
            case 0:
                androidx.glance.appwidget.lazy.f item = (androidx.glance.appwidget.lazy.f) obj;
                ((Number) obj3).intValue();
                Intrinsics.checkNotNullParameter(item, "$this$item");
                androidx.appcompat.view.a aVar = this.c;
                _COROUTINE.a.e(this.b, this.d, aVar, (InterfaceC0806l) obj2, 0);
                break;
            default:
                androidx.glance.layout.g Column = (androidx.glance.layout.g) obj;
                InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj2;
                ((Number) obj3).intValue();
                Intrinsics.checkNotNullParameter(Column, "$this$Column");
                C2 c2 = this.b;
                androidx.appcompat.view.a aVar2 = this.c;
                _COROUTINE.a.a(c2, aVar2, interfaceC0806l, 0);
                _COROUTINE.a.b(this.d, aVar2, interfaceC0806l, 0);
                break;
        }
        return Unit.a;
    }

    public E(C2 c2, B2 b2, androidx.appcompat.view.a aVar) {
        this.b = c2;
        this.d = b2;
        this.c = aVar;
    }
}

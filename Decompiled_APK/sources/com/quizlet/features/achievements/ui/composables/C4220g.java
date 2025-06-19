package com.quizlet.features.achievements.ui.composables;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: com.quizlet.features.achievements.ui.composables.g, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class C4220g implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ String b;
    public final /* synthetic */ String c;
    public final /* synthetic */ String d;

    public /* synthetic */ C4220g(String str, int i, String str2, String str3, int i2) {
        this.a = i2;
        this.b = str;
        this.c = str2;
        this.d = str3;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        int i = this.a;
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
        ((Integer) obj2).getClass();
        switch (i) {
            case 0:
                com.facebook.appevents.m.d(this.b, this.c, this.d, interfaceC0806l, C0776c.H(1));
                break;
            default:
                com.facebook.appevents.m.e(this.b, this.c, this.d, interfaceC0806l, C0776c.H(1));
                break;
        }
        return Unit.a;
    }
}

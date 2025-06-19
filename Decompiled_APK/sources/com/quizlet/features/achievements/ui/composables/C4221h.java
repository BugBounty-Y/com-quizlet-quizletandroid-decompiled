package com.quizlet.features.achievements.ui.composables;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.graphics.C0861v;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: com.quizlet.features.achievements.ui.composables.h, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class C4221h implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ kotlinx.collections.immutable.b b;
    public final /* synthetic */ String c;
    public final /* synthetic */ String d;
    public final /* synthetic */ String e;
    public final /* synthetic */ long f;
    public final /* synthetic */ Integer g;
    public final /* synthetic */ C0861v h;
    public final /* synthetic */ int i;
    public final /* synthetic */ int j;

    public /* synthetic */ C4221h(kotlinx.collections.immutable.b bVar, String str, String str2, String str3, long j, Integer num, C0861v c0861v, int i, int i2, int i3, int i4) {
        this.a = i4;
        this.b = bVar;
        this.c = str;
        this.d = str2;
        this.e = str3;
        this.f = j;
        this.g = num;
        this.h = c0861v;
        this.i = i;
        this.j = i3;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(1);
                String str = this.c;
                String str2 = this.d;
                String str3 = this.e;
                int i = this.i;
                int i2 = this.j;
                com.facebook.appevents.m.g(this.b, str, str2, str3, this.f, this.g, this.h, i, (InterfaceC0806l) obj, iH, i2);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(1);
                String str4 = this.c;
                String str5 = this.d;
                String str6 = this.e;
                int i3 = this.i;
                int i4 = this.j;
                com.facebook.appevents.m.h(this.b, str4, str5, str6, this.f, this.g, this.h, i3, (InterfaceC0806l) obj, iH2, i4);
                break;
        }
        return Unit.a;
    }
}

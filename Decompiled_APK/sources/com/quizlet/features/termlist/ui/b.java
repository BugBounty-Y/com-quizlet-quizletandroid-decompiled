package com.quizlet.features.termlist.ui;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_common.I3;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.functions.d;

/* loaded from: classes3.dex */
public final /* synthetic */ class b implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ long b;
    public final /* synthetic */ com.quizlet.features.infra.models.a c;
    public final /* synthetic */ Boolean d;
    public final /* synthetic */ boolean e;
    public final /* synthetic */ String f;
    public final /* synthetic */ String g;
    public final /* synthetic */ Function2 h;
    public final /* synthetic */ d i;
    public final /* synthetic */ kotlin.jvm.functions.c j;
    public final /* synthetic */ com.quizlet.features.infra.models.a k;
    public final /* synthetic */ String l;

    public /* synthetic */ b(long j, com.quizlet.features.infra.models.a aVar, Boolean bool, boolean z, String str, String str2, Function2 function2, d dVar, kotlin.jvm.functions.c cVar, com.quizlet.features.infra.models.a aVar2, String str3, int i, int i2) {
        this.a = i2;
        this.b = j;
        this.c = aVar;
        this.d = bool;
        this.e = z;
        this.f = str;
        this.g = str2;
        this.h = function2;
        this.i = dVar;
        this.j = cVar;
        this.k = aVar2;
        this.l = str3;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(1);
                I3.a(this.b, this.c, this.d, this.e, this.f, this.g, this.h, this.i, this.j, this.k, this.l, interfaceC0806l, iH);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(1);
                I3.b(this.b, this.c, this.d, this.e, this.f, this.g, this.h, this.i, this.j, this.k, this.l, interfaceC0806l, iH2);
                break;
        }
        return Unit.a;
    }
}

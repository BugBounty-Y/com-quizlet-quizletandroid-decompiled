package com.quizlet.shared.httpclient;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.r;
import kotlin.p;
import kotlinx.coroutines.C5028l;

/* loaded from: classes3.dex */
public final class f extends r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ C5028l b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ f(C5028l c5028l, int i) {
        super(1);
        this.a = i;
        this.b = c5028l;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        C5028l c5028l = this.b;
        switch (this.a) {
            case 0:
                b it2 = (b) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                if (!c5028l.x()) {
                    p pVar = kotlin.r.b;
                    c5028l.resumeWith(it2);
                }
                break;
            case 1:
                a it3 = (a) obj;
                Intrinsics.checkNotNullParameter(it3, "it");
                if (!c5028l.x()) {
                    p pVar2 = kotlin.r.b;
                    c5028l.resumeWith(Z.b(it3.a));
                }
                break;
            case 2:
                b it4 = (b) obj;
                Intrinsics.checkNotNullParameter(it4, "it");
                if (!c5028l.x()) {
                    p pVar3 = kotlin.r.b;
                    c5028l.resumeWith(it4);
                }
                break;
            default:
                a it5 = (a) obj;
                Intrinsics.checkNotNullParameter(it5, "it");
                if (!c5028l.x()) {
                    p pVar4 = kotlin.r.b;
                    c5028l.resumeWith(Z.b(it5.a));
                }
                break;
        }
        return Unit.a;
    }
}

package com.quizlet.features.emailconfirmation.ui.composables;

import androidx.compose.ui.layout.V;
import java.util.LinkedHashMap;
import java.util.List;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* loaded from: classes2.dex */
public final class j extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ androidx.constraintlayout.compose.j b;
    public final /* synthetic */ List c;
    public final /* synthetic */ LinkedHashMap d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ j(androidx.constraintlayout.compose.j jVar, List list, LinkedHashMap linkedHashMap, int i) {
        super(1);
        this.a = i;
        this.b = jVar;
        this.c = list;
        this.d = linkedHashMap;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                LinkedHashMap linkedHashMap = this.d;
                this.b.e((V) obj, this.c, linkedHashMap);
                break;
            case 1:
                LinkedHashMap linkedHashMap2 = this.d;
                this.b.e((V) obj, this.c, linkedHashMap2);
                break;
            case 2:
                LinkedHashMap linkedHashMap3 = this.d;
                this.b.e((V) obj, this.c, linkedHashMap3);
                break;
            default:
                LinkedHashMap linkedHashMap4 = this.d;
                this.b.e((V) obj, this.c, linkedHashMap4);
                break;
        }
        return Unit.a;
    }
}

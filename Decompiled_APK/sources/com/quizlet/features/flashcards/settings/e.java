package com.quizlet.features.flashcards.settings;

import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3274u5;
import com.quizlet.quizletandroid.R;
import java.util.ArrayList;
import kotlin.Unit;
import kotlin.collections.C4933y;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes2.dex */
public final /* synthetic */ class e implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ j b;

    public /* synthetic */ e(j jVar, int i) {
        this.a = i;
        this.b = jVar;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        com.quizlet.qutils.string.g fVar;
        com.quizlet.qutils.string.g fVar2;
        Object value;
        com.quizlet.features.infra.models.flashcards.d dVar;
        switch (this.a) {
            case 0:
                com.quizlet.features.infra.models.flashcards.d it2 = (com.quizlet.features.infra.models.flashcards.d) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                j jVar = this.b;
                com.quizlet.features.infra.basestudy.manager.f fVar3 = jVar.g;
                if (!fVar3.x.d()) {
                    fVar3 = null;
                }
                boolean z = false;
                if (fVar3 != null) {
                    fVar = AbstractC3274u5.f(jVar.e.h(fVar3));
                } else {
                    Object[] args = new Object[0];
                    Intrinsics.checkNotNullParameter(args, "args");
                    fVar = new com.quizlet.qutils.string.f(R.string.term, C4933y.P(args));
                }
                if (fVar3 != null) {
                    fVar2 = AbstractC3274u5.f(jVar.f.e(fVar3));
                } else {
                    Object[] args2 = new Object[0];
                    Intrinsics.checkNotNullParameter(args2, "args");
                    fVar2 = new com.quizlet.qutils.string.f(R.string.definition, C4933y.P(args2));
                }
                ArrayList arrayList = jVar.l;
                a aVar = new a(arrayList, it2.a, fVar, fVar2);
                a aVar2 = arrayList.size() <= 2 ? null : new a(arrayList, it2.b, fVar, fVar2);
                n nVar = jVar.k ? new n(it2.g) : null;
                boolean z2 = it2.f;
                if (it2.d && it2.c) {
                    z = true;
                }
                return new k(aVar, aVar2, z2, z, nVar, it2.b());
            default:
                j jVar2 = this.b;
                s0 s0Var = jVar2.m;
                do {
                    value = s0Var.getValue();
                    boolean z3 = jVar2.k;
                    dVar = jVar2.h;
                    if (!z3) {
                        dVar.g = false;
                    }
                } while (!s0Var.k(value, dVar));
                return Unit.a;
        }
    }
}

package com.quizlet.features.match.viewmodel;

import com.quizlet.features.match.data.C4366w;
import com.quizlet.features.match.data.EnumC4369z;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e implements io.reactivex.rxjava3.functions.d {
    public final /* synthetic */ int a;
    public final /* synthetic */ f b;

    public /* synthetic */ e(f fVar, int i) {
        this.a = i;
        this.b = fVar;
    }

    @Override // io.reactivex.rxjava3.functions.d
    public final void accept(Object obj) {
        switch (this.a) {
            case 0:
                EnumC4369z it2 = (EnumC4369z) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                this.b.f = true;
                break;
            default:
                EnumC4369z gameType = (EnumC4369z) obj;
                Intrinsics.checkNotNullParameter(gameType, "gameType");
                f fVar = this.b;
                fVar.d.o(new C4366w(gameType));
                break;
        }
    }
}

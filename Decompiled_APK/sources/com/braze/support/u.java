package com.braze.support;

import com.comscore.streaming.EventType;
import com.quizlet.features.practicetest.takingtest.data.C4413g;
import com.quizlet.features.practicetest.takingtest.data.C4414h;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final /* synthetic */ class u implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Function0 b;

    public /* synthetic */ u(int i, Function0 function0) {
        this.a = i;
        this.b = function0;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                break;
            case 1:
                break;
            case 2:
                break;
            case 3:
                this.b.invoke();
                break;
            case 4:
                this.b.invoke();
                break;
            case 5:
                this.b.invoke();
                break;
            case 6:
                io.reactivex.rxjava3.core.i iVarM = ((io.reactivex.rxjava3.core.p) this.b.invoke()).m();
                Intrinsics.checkNotNullExpressionValue(iVarM, "toObservable(...)");
                break;
            case 7:
                io.reactivex.rxjava3.core.i iVarM2 = ((io.reactivex.rxjava3.core.p) this.b.invoke()).m();
                Intrinsics.checkNotNullExpressionValue(iVarM2, "toObservable(...)");
                break;
            case 8:
                this.b.invoke();
                break;
            case 9:
                Function0 function0 = this.b;
                if (function0 != null) {
                    function0.invoke();
                }
                break;
            case 10:
                break;
            case 11:
                break;
            case 12:
                this.b.invoke();
                break;
            case 13:
                this.b.invoke();
                break;
            case 14:
                this.b.invoke();
                break;
            case 15:
                this.b.invoke();
                break;
            case 16:
                this.b.invoke();
                break;
            case 17:
                this.b.invoke();
                break;
            case 18:
                this.b.invoke();
                break;
            case 19:
                this.b.invoke();
                break;
            case 20:
                this.b.invoke();
                break;
            case 21:
                this.b.invoke();
                break;
            case EventType.WINDOW_STATE /* 22 */:
                this.b.invoke();
                break;
            case EventType.AUDIO /* 23 */:
                C4413g c4413g = (C4413g) this.b.invoke();
                break;
            case EventType.VIDEO /* 24 */:
                this.b.invoke();
                break;
            case EventType.SUBS /* 25 */:
                this.b.invoke();
                break;
            case EventType.CDN /* 26 */:
                C4414h c4414h = (C4414h) this.b.invoke();
                if (c4414h == null || (str = c4414h.a) == null) {
                    String str = "";
                }
                break;
            case 27:
                this.b.invoke();
                break;
            case 28:
                this.b.invoke();
                break;
            default:
                this.b.invoke();
                break;
        }
        return Unit.a;
    }
}

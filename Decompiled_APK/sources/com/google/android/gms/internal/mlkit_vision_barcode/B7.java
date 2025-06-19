package com.google.android.gms.internal.mlkit_vision_barcode;

import androidx.glance.appwidget.protobuf.C1194f;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class B7 {
    public static final /* synthetic */ int a = 0;

    public static String a(C1194f c1194f) {
        StringBuilder sb = new StringBuilder(c1194f.size());
        for (int i = 0; i < c1194f.size(); i++) {
            byte bA = c1194f.a(i);
            if (bA == 34) {
                sb.append("\\\"");
            } else if (bA == 39) {
                sb.append("\\'");
            } else if (bA != 92) {
                switch (bA) {
                    case 7:
                        sb.append("\\a");
                        break;
                    case 8:
                        sb.append("\\b");
                        break;
                    case 9:
                        sb.append("\\t");
                        break;
                    case 10:
                        sb.append("\\n");
                        break;
                    case 11:
                        sb.append("\\v");
                        break;
                    case 12:
                        sb.append("\\f");
                        break;
                    case 13:
                        sb.append("\\r");
                        break;
                    default:
                        if (bA < 32 || bA > 126) {
                            sb.append('\\');
                            sb.append((char) (((bA >>> 6) & 3) + 48));
                            sb.append((char) (((bA >>> 3) & 7) + 48));
                            sb.append((char) ((bA & 7) + 48));
                            break;
                        } else {
                            sb.append((char) bA);
                            break;
                        }
                }
            } else {
                sb.append("\\\\");
            }
        }
        return sb.toString();
    }

    public static final io.reactivex.rxjava3.internal.observers.e b(io.reactivex.rxjava3.core.p subscribeBy, Function1 onError, Function1 onSuccess) {
        com.quizlet.quizletandroid.ui.setpage.terms.c cVar;
        com.quizlet.quizletandroid.ui.setpage.terms.c cVar2;
        Intrinsics.checkNotNullParameter(subscribeBy, "$this$subscribeBy");
        Intrinsics.checkNotNullParameter(onError, "onError");
        Intrinsics.checkNotNullParameter(onSuccess, "onSuccess");
        if (onSuccess == io.reactivex.rxjava3.kotlin.c.c) {
            cVar = io.reactivex.rxjava3.internal.functions.d.d;
            Intrinsics.checkNotNullExpressionValue(cVar, "Functions.emptyConsumer()");
        } else {
            cVar = new com.quizlet.quizletandroid.ui.setpage.terms.c(onSuccess, 11);
        }
        if (onError == io.reactivex.rxjava3.kotlin.c.b) {
            cVar2 = io.reactivex.rxjava3.internal.functions.d.e;
            Intrinsics.checkNotNullExpressionValue(cVar2, "Functions.ON_ERROR_MISSING");
        } else {
            cVar2 = new com.quizlet.quizletandroid.ui.setpage.terms.c(onError, 11);
        }
        io.reactivex.rxjava3.internal.observers.e eVarI = subscribeBy.i(cVar, cVar2);
        Intrinsics.checkNotNullExpressionValue(eVarI, "subscribe(onSuccess.asCo…rror.asOnErrorConsumer())");
        return eVarI;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r0v1, types: [io.reactivex.rxjava3.kotlin.b] */
    public static io.reactivex.rxjava3.disposables.b c(io.reactivex.rxjava3.core.a subscribeBy, Function1 onError, com.quizlet.data.repository.explanations.exercise.a onComplete, int i) {
        io.reactivex.rxjava3.kotlin.d dVar;
        int i2 = i & 1;
        io.reactivex.rxjava3.kotlin.c cVar = io.reactivex.rxjava3.kotlin.c.b;
        if (i2 != 0) {
            onError = cVar;
        }
        int i3 = i & 2;
        ?? r0 = io.reactivex.rxjava3.kotlin.b.a;
        if (i3 != 0) {
            onComplete = r0;
        }
        Intrinsics.checkNotNullParameter(subscribeBy, "$this$subscribeBy");
        Intrinsics.checkNotNullParameter(onError, "onError");
        Intrinsics.checkNotNullParameter(onComplete, "onComplete");
        if (onError == cVar && onComplete == r0) {
            io.reactivex.rxjava3.disposables.b bVarE = subscribeBy.e();
            Intrinsics.checkNotNullExpressionValue(bVarE, "subscribe()");
            return bVarE;
        }
        if (onError == cVar) {
            io.reactivex.rxjava3.internal.observers.e eVarF = subscribeBy.f(new io.reactivex.rxjava3.kotlin.d(onComplete), io.reactivex.rxjava3.internal.functions.d.e);
            Intrinsics.checkNotNullExpressionValue(eVarF, "subscribe(onComplete)");
            return eVarF;
        }
        if (onComplete == r0) {
            dVar = io.reactivex.rxjava3.internal.functions.d.c;
            Intrinsics.checkNotNullExpressionValue(dVar, "Functions.EMPTY_ACTION");
        } else {
            dVar = new io.reactivex.rxjava3.kotlin.d(onComplete);
        }
        io.reactivex.rxjava3.internal.observers.e eVarF2 = subscribeBy.f(dVar, new com.quizlet.quizletandroid.ui.setpage.terms.c(onError, 11));
        Intrinsics.checkNotNullExpressionValue(eVarF2, "subscribe(onComplete.asO…ion(), Consumer(onError))");
        return eVarF2;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r2v0, types: [io.reactivex.rxjava3.kotlin.b] */
    public static io.reactivex.rxjava3.internal.observers.h d(io.reactivex.rxjava3.core.i subscribeBy, Function1 onError, com.quizlet.quizletandroid.ui.globalnav.composable.n onComplete, Function1 onNext, int i) {
        com.quizlet.quizletandroid.ui.setpage.terms.c cVar;
        com.quizlet.quizletandroid.ui.setpage.terms.c cVar2;
        io.reactivex.rxjava3.kotlin.d dVar;
        int i2 = i & 1;
        io.reactivex.rxjava3.kotlin.c cVar3 = io.reactivex.rxjava3.kotlin.c.b;
        if (i2 != 0) {
            onError = cVar3;
        }
        int i3 = i & 2;
        ?? r2 = io.reactivex.rxjava3.kotlin.b.a;
        if (i3 != 0) {
            onComplete = r2;
        }
        int i4 = i & 4;
        io.reactivex.rxjava3.kotlin.c cVar4 = io.reactivex.rxjava3.kotlin.c.c;
        if (i4 != 0) {
            onNext = cVar4;
        }
        Intrinsics.checkNotNullParameter(subscribeBy, "$this$subscribeBy");
        Intrinsics.checkNotNullParameter(onError, "onError");
        Intrinsics.checkNotNullParameter(onComplete, "onComplete");
        Intrinsics.checkNotNullParameter(onNext, "onNext");
        if (onNext == cVar4) {
            cVar = io.reactivex.rxjava3.internal.functions.d.d;
            Intrinsics.checkNotNullExpressionValue(cVar, "Functions.emptyConsumer()");
        } else {
            cVar = new com.quizlet.quizletandroid.ui.setpage.terms.c(onNext, 11);
        }
        if (onError == cVar3) {
            cVar2 = io.reactivex.rxjava3.internal.functions.d.e;
            Intrinsics.checkNotNullExpressionValue(cVar2, "Functions.ON_ERROR_MISSING");
        } else {
            cVar2 = new com.quizlet.quizletandroid.ui.setpage.terms.c(onError, 11);
        }
        if (onComplete == r2) {
            dVar = io.reactivex.rxjava3.internal.functions.d.c;
            Intrinsics.checkNotNullExpressionValue(dVar, "Functions.EMPTY_ACTION");
        } else {
            dVar = new io.reactivex.rxjava3.kotlin.d(onComplete);
        }
        io.reactivex.rxjava3.disposables.b bVarU = subscribeBy.u(cVar, cVar2, dVar);
        Intrinsics.checkNotNullExpressionValue(bVarU, "subscribe(onNext.asConsu…ete.asOnCompleteAction())");
        return (io.reactivex.rxjava3.internal.observers.h) bVarU;
    }
}

package com.airbnb.lottie.compose;

import androidx.glance.appwidget.protobuf.Z;
import com.airbnb.lottie.x;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C5028l;

/* loaded from: classes.dex */
public final class p implements x {
    public final /* synthetic */ int a;
    public final /* synthetic */ C5028l b;

    public /* synthetic */ p(C5028l c5028l, int i) {
        this.a = i;
        this.b = c5028l;
    }

    @Override // com.airbnb.lottie.x
    public final void onResult(Object obj) {
        C5028l c5028l = this.b;
        switch (this.a) {
            case 0:
                if (!c5028l.y()) {
                    kotlin.p pVar = kotlin.r.b;
                    c5028l.resumeWith(obj);
                    break;
                }
                break;
            default:
                Throwable th = (Throwable) obj;
                if (!c5028l.y()) {
                    kotlin.p pVar2 = kotlin.r.b;
                    Intrinsics.d(th);
                    c5028l.resumeWith(Z.b(th));
                    break;
                }
                break;
        }
    }
}

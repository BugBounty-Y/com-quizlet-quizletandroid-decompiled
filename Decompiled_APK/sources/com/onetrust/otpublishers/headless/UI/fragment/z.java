package com.onetrust.otpublishers.headless.UI.fragment;

import androidx.lifecycle.X;
import androidx.lifecycle.Z;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final /* synthetic */ class z implements Z {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;

    public /* synthetic */ z(int i, Object obj, Object obj2) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
    }

    @Override // androidx.lifecycle.Z
    public final void a(Object obj) {
        Object obj2 = this.c;
        Object obj3 = this.b;
        switch (this.a) {
            case 0:
                Map it2 = (Map) obj;
                com.google.firebase.perf.logging.b bVar = D.D;
                com.onetrust.otpublishers.headless.UI.viewmodel.e this_with = (com.onetrust.otpublishers.headless.UI.viewmodel.e) obj3;
                Intrinsics.checkNotNullParameter(this_with, "$this_with");
                D this$0 = (D) obj2;
                Intrinsics.checkNotNullParameter(this$0, "this$0");
                if (this_with.C()) {
                    Intrinsics.checkNotNullExpressionValue(it2, "it");
                    this$0.V(it2);
                    break;
                }
                break;
            case 1:
                Map it3 = (Map) obj;
                com.google.firebase.perf.logging.b bVar2 = D.D;
                com.onetrust.otpublishers.headless.UI.viewmodel.e this_with2 = (com.onetrust.otpublishers.headless.UI.viewmodel.e) obj3;
                Intrinsics.checkNotNullParameter(this_with2, "$this_with");
                D this$02 = (D) obj2;
                Intrinsics.checkNotNullParameter(this$02, "this$0");
                if (!this_with2.C()) {
                    Intrinsics.checkNotNullExpressionValue(it3, "it");
                    this$02.V(it3);
                    break;
                }
                break;
            default:
                if (((AtomicBoolean) ((X) obj3).m).compareAndSet(true, false)) {
                    ((Z) obj2).a(obj);
                    break;
                }
                break;
        }
    }
}

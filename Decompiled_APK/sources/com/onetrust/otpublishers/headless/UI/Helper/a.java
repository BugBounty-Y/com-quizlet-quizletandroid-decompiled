package com.onetrust.otpublishers.headless.UI.Helper;

import androidx.lifecycle.InterfaceC1250k;
import androidx.lifecycle.J;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class a implements InterfaceC1250k {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ a(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // androidx.lifecycle.InterfaceC1250k
    public final void onDestroy(J owner) {
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(owner, "owner");
                ((com.quizlet.data.repository.user.a) this.b).d = null;
                break;
            default:
                Intrinsics.checkNotNullParameter(owner, "owner");
                ((Function0) this.b).invoke();
                break;
        }
    }
}

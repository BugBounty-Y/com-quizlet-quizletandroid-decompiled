package com.onetrust.otpublishers.headless.UI.Helper;

import androidx.camera.camera2.internal.D;
import androidx.lifecycle.InterfaceC1250k;
import androidx.lifecycle.J;
import com.google.android.material.bottomsheet.i;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class b implements InterfaceC1250k {
    public final D a;
    public final /* synthetic */ com.quizlet.data.repository.user.a b;

    public b(com.quizlet.data.repository.user.a aVar) {
        this.b = aVar;
        this.a = new D(aVar, 4);
    }

    @Override // androidx.lifecycle.InterfaceC1250k
    public final void onCreate(J owner) {
        Intrinsics.checkNotNullParameter(owner, "owner");
        ((i) this.b.b).getViewLifecycleOwnerLiveData().g(this.a);
    }

    @Override // androidx.lifecycle.InterfaceC1250k
    public final void onDestroy(J owner) {
        Intrinsics.checkNotNullParameter(owner, "owner");
        ((i) this.b.b).getViewLifecycleOwnerLiveData().k(this.a);
    }
}

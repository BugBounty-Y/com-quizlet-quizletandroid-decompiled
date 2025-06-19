package com.quizlet.baseui.base;

import android.content.Context;
import androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t;
import com.google.android.gms.internal.mlkit_vision_barcode.J6;
import com.quizlet.quizletandroid.ui.common.ads.C4636c;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes2.dex */
public abstract class BaseDaggerDialogFragment extends DialogInterfaceOnCancelListenerC1151t implements dagger.android.c {
    public C4636c q;
    public final io.reactivex.rxjava3.disposables.a r = new io.reactivex.rxjava3.disposables.a();
    public final io.reactivex.rxjava3.disposables.a s = new io.reactivex.rxjava3.disposables.a();
    public final io.reactivex.rxjava3.disposables.a t = new io.reactivex.rxjava3.disposables.a();
    public final io.reactivex.rxjava3.disposables.a u = new io.reactivex.rxjava3.disposables.a();

    @Override // dagger.android.c
    public final C4636c c() {
        C4636c c4636c = this.q;
        if (c4636c != null) {
            return c4636c;
        }
        Intrinsics.m("androidInjector");
        throw null;
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, androidx.fragment.app.Fragment
    public void onAttach(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        if (!(this instanceof dagger.hilt.android.internal.migration.a)) {
            J6.c(this);
        }
        super.onAttach(context);
    }

    @Override // androidx.fragment.app.Fragment
    public final void onDestroy() {
        super.onDestroy();
        this.t.d();
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, androidx.fragment.app.Fragment
    public void onDestroyView() {
        super.onDestroyView();
        this.u.d();
    }

    @Override // androidx.fragment.app.Fragment
    public final void onPause() {
        super.onPause();
        this.r.d();
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, androidx.fragment.app.Fragment
    public final void onStop() {
        super.onStop();
        this.s.d();
    }
}

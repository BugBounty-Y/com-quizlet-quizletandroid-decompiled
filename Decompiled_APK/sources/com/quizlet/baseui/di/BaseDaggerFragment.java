package com.quizlet.baseui.di;

import android.content.Context;
import androidx.fragment.app.Fragment;
import com.google.android.gms.internal.mlkit_vision_barcode.J6;
import com.quizlet.quizletandroid.ui.common.ads.C4636c;
import dagger.android.c;
import dagger.hilt.android.internal.migration.a;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes2.dex */
public abstract class BaseDaggerFragment extends Fragment implements c {
    public C4636c a;

    @Override // dagger.android.c
    public final C4636c c() {
        C4636c c4636c = this.a;
        if (c4636c != null) {
            return c4636c;
        }
        Intrinsics.m("androidInjector");
        throw null;
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // androidx.fragment.app.Fragment
    public void onAttach(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        boolean z = this instanceof a;
        if (!z) {
            J6.c(this);
        }
        super.onAttach(context);
        if (z) {
            Class<?> cls = getClass();
            if (z) {
                return;
            }
            throw new IllegalArgumentException("'" + cls + "' is not an optionally injected android entry point. Check that you have annotated the class with both @AndroidEntryPoint and @OptionalInject.");
        }
    }
}

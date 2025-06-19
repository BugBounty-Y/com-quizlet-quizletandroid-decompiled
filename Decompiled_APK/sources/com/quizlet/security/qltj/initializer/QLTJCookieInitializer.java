package com.quizlet.security.qltj.initializer;

import android.content.Context;
import androidx.datastore.core.InterfaceC1076h;
import androidx.startup.b;
import com.google.android.gms.internal.mlkit_vision_barcode.K6;
import com.quizlet.local.datastore.preferences.J;
import com.quizlet.quizletandroid.u;
import com.quizlet.security.qltj.di.a;
import java.util.ArrayList;
import java.util.List;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;
import kotlinx.coroutines.internal.d;
import okhttp3.n;

@Metadata
/* loaded from: classes3.dex */
public final class QLTJCookieInitializer implements b {
    @Override // androidx.startup.b
    public final Object create(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        u uVar = (u) ((a) K6.b(a.class, context));
        n nVar = (n) uVar.M.get();
        J j = new J((InterfaceC1076h) uVar.L.get());
        d dVarV = uVar.V();
        E.A(dVarV, null, null, new com.quizlet.security.qltj.core.a(new com.quizlet.remote.model.union.folderwithcreator.b(nVar, j, dVarV), null), 3);
        return Unit.a;
    }

    @Override // androidx.startup.b
    public final List dependencies() {
        return new ArrayList();
    }
}

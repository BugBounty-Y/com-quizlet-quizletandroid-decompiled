package com.onetrust.otpublishers.headless.UI.viewmodel;

import android.app.Application;
import androidx.lifecycle.w0;
import androidx.lifecycle.y0;
import com.google.common.collect.C;
import kotlin.collections.V;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class c implements y0 {
    public final /* synthetic */ int a;
    public final Object b;

    public c(Application application, int i) {
        this.a = i;
        switch (i) {
            case 1:
                Intrinsics.checkNotNullParameter(application, "application");
                this.b = application;
                break;
            default:
                Intrinsics.checkNotNullParameter(application, "application");
                this.b = application;
                break;
        }
    }

    @Override // androidx.lifecycle.y0
    public final w0 a(Class modelClass) {
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(modelClass, "modelClass");
                Application application = (Application) this.b;
                return new d(application, new com.onetrust.otpublishers.headless.Internal.Preferences.e(application));
            case 1:
                Intrinsics.checkNotNullParameter(modelClass, "modelClass");
                Application application2 = (Application) this.b;
                return new e(application2, new com.onetrust.otpublishers.headless.Internal.Preferences.e(application2));
            default:
                Intrinsics.checkNotNullParameter(modelClass, "modelClass");
                Object obj = ((javax.inject.a) V.d(modelClass, (C) this.b)).get();
                Intrinsics.e(obj, "null cannot be cast to non-null type T of com.quizlet.viewmodel.factory.ViewModelFactory.create");
                return (w0) obj;
        }
    }

    public c(C creators) {
        this.a = 2;
        Intrinsics.checkNotNullParameter(creators, "creators");
        this.b = creators;
    }
}

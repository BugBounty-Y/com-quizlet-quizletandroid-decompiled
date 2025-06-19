package com.google.android.datatransport.runtime.backends;

import android.content.Context;
import com.google.android.datatransport.runtime.scheduling.persistence.i;

/* loaded from: classes2.dex */
public final class e implements com.google.android.datatransport.runtime.dagger.internal.b {
    public final /* synthetic */ int a;
    public final Object b;

    public /* synthetic */ e(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // javax.inject.a
    public final Object get() {
        switch (this.a) {
            case 0:
                return new d((Context) ((e) this.b).b, new com.quizlet.shared.usecase.folderstudymaterials.c(8), new com.quizlet.shared.usecase.folderstudymaterials.b(8));
            case 1:
                String packageName = ((Context) ((e) this.b).b).getPackageName();
                if (packageName != null) {
                    return packageName;
                }
                throw new NullPointerException("Cannot return null from a non-@Nullable @Provides method");
            case 2:
                return new i((Context) ((e) this.b).b, "com.google.android.datatransport.events", Integer.valueOf(i.d).intValue());
            default:
                return this.b;
        }
    }
}

package com.quizlet.baseui.base;

import android.content.pm.PackageManager;
import android.os.Bundle;
import androidx.appcompat.app.AbstractActivityC0055k;
import androidx.lifecycle.C;
import com.quizlet.quizletandroid.managers.h;
import com.quizlet.quizletandroid.ui.base.g;
import java.lang.reflect.InvocationTargetException;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class c extends AbstractActivityC0055k {
    public g c;

    @Override // androidx.fragment.app.I, androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        timber.log.c.a.g("Creating activity %s with extras %s", y(), String.valueOf(getIntent().getExtras()));
        g gVarX = x();
        C lifecycle = getLifecycle();
        Intrinsics.checkNotNullParameter(lifecycle, "lifecycle");
        lifecycle.a(gVarX.c);
    }

    @Override // androidx.appcompat.app.AbstractActivityC0055k, androidx.fragment.app.I, android.app.Activity
    public void onDestroy() {
        timber.log.c.a.g("Destroying activity %s", y());
        super.onDestroy();
    }

    @Override // androidx.fragment.app.I, android.app.Activity
    public final void onPause() {
        timber.log.c.a.g("Pausing activity %s", y());
        x().a(this, getResources().getConfiguration().orientation == 2);
        super.onPause();
    }

    @Override // androidx.appcompat.app.AbstractActivityC0055k, android.app.Activity
    public final void onPostCreate(Bundle bundle) throws IllegalAccessException, NoSuchMethodException, SecurityException, IllegalArgumentException, InvocationTargetException {
        super.onPostCreate(bundle);
        x().b(this);
    }

    @Override // androidx.fragment.app.I, android.app.Activity
    public void onResume() {
        super.onResume();
        timber.log.c.a.g("Resuming activity %s", y());
        x().c(this, y(), getResources().getConfiguration().orientation == 2);
    }

    @Override // androidx.appcompat.app.AbstractActivityC0055k, androidx.fragment.app.I, android.app.Activity
    public final void onStart() throws PackageManager.NameNotFoundException {
        super.onStart();
        timber.log.c.a.g("Starting activity %s", y());
        x().d(y(), true);
    }

    @Override // androidx.appcompat.app.AbstractActivityC0055k, androidx.fragment.app.I, android.app.Activity
    public final void onStop() throws IllegalAccessException, NoSuchMethodException, SecurityException, IllegalArgumentException, InvocationTargetException {
        timber.log.c.a.g("Stopping activity %s", y());
        h hVar = x().h;
        int i = hVar.a;
        if (i > 0) {
            hVar.a = i - 1;
        }
        if (hVar.a == 0) {
            hVar.b.b(Boolean.FALSE);
        }
        super.onStop();
    }

    public final g x() {
        g gVar = this.c;
        if (gVar != null) {
            return gVar;
        }
        Intrinsics.m("baseActivityDelegate");
        throw null;
    }

    public abstract String y();
}

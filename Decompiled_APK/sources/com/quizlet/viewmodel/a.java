package com.quizlet.viewmodel;

import com.google.android.gms.measurement.internal.Z;
import io.reactivex.rxjava3.subjects.r;
import kotlin.Unit;

/* loaded from: classes3.dex */
public abstract class a extends b {
    public final r c = Z.f("create(...)");

    @Override // com.quizlet.viewmodel.b, androidx.lifecycle.w0
    public void z() {
        super.z();
        this.c.onSuccess(Unit.a);
    }
}
